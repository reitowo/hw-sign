package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// verifyKeyAttestation verifies key attestation data
func verifyKeyAttestation(attestation KeyAttestationRequest) TPMVerificationResult {
	result := TPMVerificationResult{
		VerificationTime: time.Now().UTC().Format(time.RFC3339),
		Warnings:         []string{},
	}

	// First verify the certificate chain if provided
	if attestation.CertChain.TPMInfo.Manufacturer != "" {
		chainResult := verifyTPMCertificateChain(attestation.CertChain)
		result.TPMManufacturer = chainResult.TPMManufacturer
		result.TPMVersion = chainResult.TPMVersion
		result.EKCertValid = chainResult.EKCertValid
		result.AIKValid = chainResult.AIKValid
		result.Warnings = append(result.Warnings, chainResult.Warnings...)
	}

	// Verify key name is present
	if attestation.KeyName == "" {
		result.Warnings = append(result.Warnings, "Key TPM2B_NAME not provided")
		result.Verified = false
		return result
	}

	keyNameBytes, err := base64.StdEncoding.DecodeString(attestation.KeyName)
	if err != nil {
		result.Warnings = append(result.Warnings, "Invalid key name encoding")
		return result
	}

	// Parse TPM2B_NAME structure
	// TPM2B_NAME consists of: size (2 bytes) + name data
	// The name data starts with the hash algorithm (2 bytes) followed by the hash
	keyNameValid := false
	if len(keyNameBytes) >= 4 {
		debugLog("verifyKeyAttestation", "Key name length: %d bytes", len(keyNameBytes))
		// For SHA-256 (algorithm 0x000B), the name would be 2 + 32 = 34 bytes
		if len(keyNameBytes) >= 34 && len(keyNameBytes) <= 68 {
			keyNameValid = true
			debugLog("verifyKeyAttestation", "Key name format looks valid")
		} else {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Unusual key name size: %d bytes", len(keyNameBytes)))
		}
	}

	// Verify TPM2_Certify: this is the authoritative proof that key is in TPM
	// The signature verification is critical - without it, KeyInTPM should NOT be true
	if attestation.AIKPub != "" && attestation.Signature != "" && attestation.CertifyInfo != "" {
		ok, warn := verifyTpm2Certify(attestation)
		if len(warn) > 0 {
			result.Warnings = append(result.Warnings, warn...)
		}
		if ok {
			debugLog("verifyKeyAttestation", "TPM2_Certify attestation verified - key is in TPM")
			result.KeyInTPM = true
			result.AIKValid = true
		} else {
			// Signature verification failed - key may NOT be in TPM
			debugLog("verifyKeyAttestation", "TPM2_Certify verification FAILED - cannot confirm key is in TPM")
			result.KeyInTPM = false
		}
	} else {
		// No TPM2_Certify data - fall back to key name validation only (weaker)
		result.Warnings = append(result.Warnings, "Missing certify_info/aik_pub/signature for TPM2_Certify verification")
		result.KeyInTPM = keyNameValid // Only trust key name format if no signature available
	}

	result.Verified = result.KeyInTPM
	return result
}

func parseTpm2bNameLike(b []byte) []byte {
	// Accept either raw NAME (e.g., 34 bytes: algId||digest) or TPM2B_NAME (u16 size + name)
	if len(b) >= 2 {
		sz := int(binary.BigEndian.Uint16(b[:2]))
		if sz > 0 && sz == len(b)-2 {
			return b[2:]
		}
	}
	return b
}

func parseCertifyInfoAttestedName(certifyInfo []byte) ([]byte, error) {
	// TPMS_ATTEST (big-endian):
	// generated (4) 0xff544347
	// type (2) TPM_ST_ATTEST_CERTIFY = 0x8017
	// qualifiedSigner TPM2B_NAME
	// extraData TPM2B_DATA
	// clockInfo TPMS_CLOCK_INFO (17)
	// firmwareVersion (8)
	// attested: TPMS_CERTIFY_INFO { name TPM2B_NAME, qualifiedName TPM2B_NAME }
	if len(certifyInfo) < 4+2 {
		return nil, errors.New("certify_info too small")
	}
	off := 0
	gen := binary.BigEndian.Uint32(certifyInfo[off : off+4])
	off += 4
	if gen != 0xff544347 {
		return nil, fmt.Errorf("unexpected generated: 0x%08x", gen)
	}
	typ := binary.BigEndian.Uint16(certifyInfo[off : off+2])
	off += 2
	if typ != 0x8017 {
		return nil, fmt.Errorf("unexpected attest type: 0x%04x", typ)
	}
	read2b := func() ([]byte, error) {
		if off+2 > len(certifyInfo) {
			return nil, errors.New("buffer underflow")
		}
		sz := int(binary.BigEndian.Uint16(certifyInfo[off : off+2]))
		off += 2
		if off+sz > len(certifyInfo) {
			return nil, errors.New("buffer underflow")
		}
		v := certifyInfo[off : off+sz]
		off += sz
		return v, nil
	}

	// qualifiedSigner, extraData
	if _, err := read2b(); err != nil {
		return nil, err
	}
	if _, err := read2b(); err != nil {
		return nil, err
	}
	// clockInfo (17)
	if off+17 > len(certifyInfo) {
		return nil, errors.New("buffer underflow clockInfo")
	}
	off += 17
	// firmwareVersion (8)
	if off+8 > len(certifyInfo) {
		return nil, errors.New("buffer underflow firmwareVersion")
	}
	off += 8

	name, err := read2b()
	if err != nil {
		return nil, err
	}
	return name, nil
}

func verifyTpm2Certify(attestation KeyAttestationRequest) (bool, []string) {
	warnings := []string{}

	aikPubBytes, err := base64.StdEncoding.DecodeString(attestation.AIKPub)
	if err != nil {
		return false, append(warnings, "Invalid aik_pub base64")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(attestation.Signature)
	if err != nil {
		return false, append(warnings, "Invalid signature base64")
	}
	certifyInfoBytes, err := base64.StdEncoding.DecodeString(attestation.CertifyInfo)
	if err != nil {
		return false, append(warnings, "Invalid certify_info base64")
	}
	keyNameBytes, err := base64.StdEncoding.DecodeString(attestation.KeyName)
	if err != nil {
		return false, append(warnings, "Invalid key_name base64")
	}

	// Parse AIK RSA public key (BCRYPT_RSAPUBLIC_BLOB or PKIX)
	var rsaPubKey *rsa.PublicKey
	if len(aikPubBytes) > 24 && binary.LittleEndian.Uint32(aikPubBytes[0:4]) == 0x31415352 {
		rsaPubKey = parseBCryptRSAPublicBlob(aikPubBytes)
	}
	if rsaPubKey == nil {
		pubKey, perr := x509.ParsePKIXPublicKey(aikPubBytes)
		if perr == nil {
			if pk, ok := pubKey.(*rsa.PublicKey); ok {
				rsaPubKey = pk
			}
		}
	}
	if rsaPubKey == nil {
		return false, append(warnings, "AIK pubkey is not RSA (unsupported)")
	}

	attestedName, err := parseCertifyInfoAttestedName(certifyInfoBytes)
	if err != nil {
		return false, append(warnings, fmt.Sprintf("Failed to parse certify_info: %v", err))
	}

	reqName := parseTpm2bNameLike(keyNameBytes)
	if !bytes.Equal(reqName, attestedName) {
		return false, append(warnings, "Attested name does not match key_name")
	}

	// Verify signature over certifyInfo hash (try SHA256 first, then SHA1)
	// TPM may use different hash algorithms depending on AIK configuration
	h256 := sha256.Sum256(certifyInfoBytes)
	if err := rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, h256[:], sigBytes); err == nil {
		debugLog("verifyTpm2Certify", "Signature verified with SHA256")
		return true, warnings
	}

	// Try SHA1 as fallback (some TPMs use SHA1 for AIK signing)
	h1 := sha1.Sum(certifyInfoBytes)
	if err := rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA1, h1[:], sigBytes); err == nil {
		debugLog("verifyTpm2Certify", "Signature verified with SHA1")
		return true, warnings
	}

	// Both failed - log details for debugging
	debugLog("verifyTpm2Certify", "Signature verification failed with both SHA256 and SHA1")
	debugLog("verifyTpm2Certify", "CertifyInfo size: %d, Signature size: %d, AIK modulus bits: %d",
		len(certifyInfoBytes), len(sigBytes), rsaPubKey.N.BitLen())

	return false, append(warnings, "Certify signature verify failed (tried SHA256 and SHA1)")
}
