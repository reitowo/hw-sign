package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// verifyTPMCertificateChain verifies the TPM certificate chain
func verifyTPMCertificateChain(chain TPMCertificateChain) TPMVerificationResult {
	result := TPMVerificationResult{
		VerificationTime: time.Now().UTC().Format(time.RFC3339),
		Warnings:         []string{},
	}

	// Check TPM manufacturer
	if chain.TPMInfo.Manufacturer != "" {
		manufacturerHex := strings.ToLower(chain.TPMInfo.Manufacturer)
		if name, ok := knownTPMManufacturers[manufacturerHex]; ok {
			result.TPMManufacturer = name
			debugLog("verifyTPMChain", "TPM manufacturer identified: %s", name)
		} else {
			// Try to decode as ASCII
			if decoded, err := hex.DecodeString(manufacturerHex); err == nil {
				result.TPMManufacturer = string(decoded)
			} else {
				result.TPMManufacturer = manufacturerHex
			}
			result.Warnings = append(result.Warnings, "Unknown TPM manufacturer")
		}
	}

	result.TPMVersion = chain.TPMInfo.TPMVersion

	// Verify EK certificate if available
	var ekCertB64 string
	if len(chain.EKCerts) > 0 {
		ekCertB64 = chain.EKCerts[0]
	} else if len(chain.EKNVCerts) > 0 {
		ekCertB64 = chain.EKNVCerts[0]
	} else if chain.NVIndexBlobs != nil {
		if b64, ok := chain.NVIndexBlobs["0x01c00002"]; ok {
			ekCertB64 = b64
		}
	}
	if ekCertB64 != "" {
		ekCertValid, warnings := verifyEKCertificateWithChain(ekCertB64, chain)
		result.EKCertValid = ekCertValid
		result.Warnings = append(result.Warnings, warnings...)
	} else if chain.EKPub != "" {
		// No certificate, but we have the public key
		result.Warnings = append(result.Warnings, "EK certificate not available, only public key present")
		result.EKCertValid = false
	} else {
		result.Warnings = append(result.Warnings, "No EK certificate or public key available")
	}

	// Verify AIK if available
	if chain.AIKPub != "" {
		result.AIKValid = verifyAIKPublicKey(chain.AIKPub)
		if !result.AIKValid {
			result.Warnings = append(result.Warnings, "AIK public key validation failed")
		}
	} else {
		result.Warnings = append(result.Warnings, "AIK not available")
	}

	// Set overall verification status
	// For now, we consider it verified if we have valid TPM info and at least EK pub or AIK
	result.Verified = (chain.EKPub != "" || len(chain.EKCerts) > 0 || len(chain.EKNVCerts) > 0 || (chain.NVIndexBlobs != nil && chain.NVIndexBlobs["0x01c00002"] != "")) &&
		chain.TPMInfo.Manufacturer != ""

	debugLog("verifyTPMChain", "Verification result: verified=%v, ek_valid=%v, aik_valid=%v",
		result.Verified, result.EKCertValid, result.AIKValid)

	return result
}

// verifyEKCertificateWithChain verifies an EK certificate using the full chain from client
func verifyEKCertificateWithChain(certBase64 string, chain TPMCertificateChain) (bool, []string) {
	warnings := []string{}

	certDER, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		return false, append(warnings, "Failed to decode EK certificate")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return false, append(warnings, fmt.Sprintf("Failed to parse EK certificate: %v", err))
	}

	// Check certificate validity period
	now := time.Now()
	if now.Before(cert.NotBefore) {
		warnings = append(warnings, "EK certificate not yet valid")
	}
	if now.After(cert.NotAfter) {
		warnings = append(warnings, "EK certificate has expired")
	}

	// Check if certificate is for TPM EK
	// EK certificates typically have specific OIDs
	hasTPMOID := false
	for _, oid := range cert.ExtKeyUsage {
		// Any extended key usage is a good sign
		debugLog("verifyEKCert", "Certificate has ExtKeyUsage: %v", oid)
		hasTPMOID = true
	}

	// Check certificate subject for TPM-related information
	if strings.Contains(cert.Subject.CommonName, "TPM") ||
		strings.Contains(cert.Subject.CommonName, "EK") ||
		strings.Contains(cert.Subject.CommonName, "Endorsement") {
		hasTPMOID = true
	}

	// Check issuer for known TPM certificate authorities
	issuer := cert.Issuer.String()
	knownIssuer := false
	if strings.Contains(issuer, "TPM") ||
		strings.Contains(issuer, "Infineon") ||
		strings.Contains(issuer, "STMicroelectronics") ||
		strings.Contains(issuer, "Nuvoton") ||
		strings.Contains(issuer, "Intel") ||
		strings.Contains(issuer, "CSME") ||
		strings.Contains(issuer, "PTT") ||
		strings.Contains(issuer, "AMD") ||
		strings.Contains(issuer, "Microsoft") {
		debugLog("verifyEKCert", "Certificate issued by known TPM CA: %s", issuer)
		knownIssuer = true
	} else {
		warnings = append(warnings, fmt.Sprintf("Unknown certificate issuer: %s", issuer))
	}

	// Build certificate pools from all available sources
	chainVerified := false
	intermediates := x509.NewCertPool()

	// Start with builtin TPM manufacturer root CAs
	roots := builtinTPMRootCAs()

	// Helper to add a cert to the right pool
	addCert := func(c *x509.Certificate, source string) {
		if c == nil {
			return
		}
		if c.Issuer.String() == c.Subject.String() {
			if err := c.CheckSignatureFrom(c); err == nil {
				debugLog("verifyEKCert", "Adding self-signed root from %s: %s", source, c.Subject.CommonName)
				roots.AddCert(c)
				return
			}
		}
		intermediates.AddCert(c)
	}

	// Add EICA certs from client (these often contain the full chain including roots)
	for _, b64 := range chain.EICACerts {
		der, derr := decodeBase64OrErr(b64)
		if derr != nil {
			continue
		}
		c, perr := x509.ParseCertificate(der)
		if perr != nil {
			continue
		}
		addCert(c, "EICA")
	}

	// Add certs from NV index blobs (0x01c001xx range contains chain certs)
	if chain.NVIndexBlobs != nil {
		for k, v := range chain.NVIndexBlobs {
			if strings.HasPrefix(strings.ToLower(k), "0x01c001") {
				der, derr := decodeBase64OrErr(v)
				if derr != nil {
					continue
				}
				certs, _ := splitConcatenatedDerCerts(der)
				for _, c := range certs {
					addCert(c, "NV-"+k)
				}
			}
		}
	}

	// Fetch additional certs via AIA URLs
	aiaCerts, aiaWarn := fetchAiaIssuerChain(cert, 6)
	warnings = append(warnings, aiaWarn...)
	for _, c := range aiaCerts {
		addCert(c, "AIA")
	}

	// Try to verify the chain
	opts := x509.VerifyOptions{Intermediates: intermediates, Roots: roots}
	if _, verr := cert.Verify(opts); verr == nil {
		debugLog("verifyEKCert", "EK certificate chain verified successfully!")
		chainVerified = true
	} else {
		debugLog("verifyEKCert", "Chain verification failed: %v", verr)
	}

	// Return true if chain verified, or if we have TPM OIDs and known issuer
	valid := chainVerified || (hasTPMOID && knownIssuer)
	if !chainVerified {
		warnings = append(warnings, "EK certificate chain not fully verified (root CA not in trust store)")
	}
	return valid, warnings
}

// verifyAIKPublicKey verifies the AIK public key format
func verifyAIKPublicKey(aikPubBase64 string) bool {
	aikPubBytes, err := base64.StdEncoding.DecodeString(aikPubBase64)
	if err != nil {
		debugLog("verifyAIK", "Failed to decode AIK public key: %v", err)
		return false
	}

	// Try to parse as BCRYPT_RSAPUBLIC_BLOB (Windows format)
	// Format: BCRYPT_RSAKEY_BLOB header + exponent + modulus
	if len(aikPubBytes) > 24 {
		// Check for RSA1 magic (0x31415352)
		magic := binary.LittleEndian.Uint32(aikPubBytes[0:4])
		if magic == 0x31415352 { // "RSA1"
			debugLog("verifyAIK", "AIK is BCRYPT_RSAPUBLIC_BLOB format")
			return true
		}
	}

	// Try to parse as PKIX format
	if pub, err := x509.ParsePKIXPublicKey(aikPubBytes); err == nil {
		switch pub.(type) {
		case *rsa.PublicKey:
			debugLog("verifyAIK", "AIK is PKIX RSA format")
			return true
		case *ecdsa.PublicKey:
			debugLog("verifyAIK", "AIK is PKIX ECDSA format")
			return true
		}
	}

	// Try raw format (just the key bytes)
	if len(aikPubBytes) >= 256 { // Minimum for RSA-2048
		debugLog("verifyAIK", "AIK appears to be raw key bytes")
		return true
	}

	debugLog("verifyAIK", "AIK format not recognized, len=%d", len(aikPubBytes))
	return false
}

// ============ EK Public Key Extraction ============

// EKPublicKey wraps either RSA or ECC public key
type EKPublicKey struct {
	RSA *rsa.PublicKey
	ECC *ecdsa.PublicKey
}

func (ek *EKPublicKey) IsRSA() bool { return ek.RSA != nil }
func (ek *EKPublicKey) IsECC() bool { return ek.ECC != nil }
func (ek *EKPublicKey) String() string {
	if ek.RSA != nil {
		return fmt.Sprintf("RSA-%d", ek.RSA.N.BitLen())
	}
	if ek.ECC != nil {
		return fmt.Sprintf("ECC-%s", ek.ECC.Curve.Params().Name)
	}
	return "nil"
}

func parseBCryptECCPublicBlob(blob []byte) *ecdsa.PublicKey {
	// BCRYPT_ECCPUBLIC_BLOB:
	// ULONG Magic (BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345 "ECS1" or BCRYPT_ECDH_PUBLIC_P256_MAGIC = 0x314B4345 "ECK1")
	// ULONG cbKey (32 for P-256)
	// BYTE X[cbKey]
	// BYTE Y[cbKey]
	if len(blob) < 8 {
		return nil
	}
	magic := binary.LittleEndian.Uint32(blob[0:4])
	cbKey := binary.LittleEndian.Uint32(blob[4:8])

	// Check for known ECC magics
	// BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345
	// BCRYPT_ECDH_PUBLIC_P256_MAGIC = 0x314B4345
	// BCRYPT_ECDSA_PUBLIC_P384_MAGIC = 0x33534345
	// BCRYPT_ECDH_PUBLIC_P384_MAGIC = 0x334B4345
	isP256 := magic == 0x31534345 || magic == 0x314B4345
	isP384 := magic == 0x33534345 || magic == 0x334B4345

	if !isP256 && !isP384 {
		return nil
	}

	expectedLen := 8 + 2*int(cbKey)
	if len(blob) < expectedLen {
		return nil
	}

	xBytes := blob[8 : 8+cbKey]
	yBytes := blob[8+cbKey : 8+2*cbKey]

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	var curve elliptic.Curve
	if isP256 {
		curve = elliptic.P256()
	} else {
		curve = elliptic.P384()
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
}

// extractEkPublicKey extracts the EK public key from the certificate chain
func extractEkPublicKey(chain TPMCertificateChain) (*EKPublicKey, *x509.Certificate, []string, error) {
	warnings := []string{}

	// Priority 1: ek_pub field (from NCRYPT_PCP_EKPUB_PROPERTY) - most reliable
	if chain.EKPub != "" {
		ekPubBytes, err := decodeBase64OrErr(chain.EKPub)
		if err == nil && len(ekPubBytes) > 8 {
			// Try BCRYPT_RSAPUBLIC_BLOB first
			magic := binary.LittleEndian.Uint32(ekPubBytes[0:4])
			if magic == 0x31415352 { // "RSA1"
				rsaPub := parseBCryptRSAPublicBlob(ekPubBytes)
				if rsaPub != nil {
					debugLog("extractEkPublicKey", "Using ek_pub (BCRYPT_RSAPUBLIC_BLOB) directly from client, bits=%d", rsaPub.N.BitLen())
					return &EKPublicKey{RSA: rsaPub}, nil, warnings, nil
				}
			}
			// Try BCRYPT_ECCPUBLIC_BLOB
			eccPub := parseBCryptECCPublicBlob(ekPubBytes)
			if eccPub != nil {
				debugLog("extractEkPublicKey", "Using ek_pub (BCRYPT_ECCPUBLIC_BLOB) directly from client, curve=%s", eccPub.Curve.Params().Name)
				return &EKPublicKey{ECC: eccPub}, nil, warnings, nil
			}
			// Try PKIX format
			if pub, perr := x509.ParsePKIXPublicKey(ekPubBytes); perr == nil {
				switch pk := pub.(type) {
				case *rsa.PublicKey:
					debugLog("extractEkPublicKey", "Using ek_pub (PKIX RSA) directly from client, bits=%d", pk.N.BitLen())
					return &EKPublicKey{RSA: pk}, nil, warnings, nil
				case *ecdsa.PublicKey:
					debugLog("extractEkPublicKey", "Using ek_pub (PKIX ECC) directly from client, curve=%s", pk.Curve.Params().Name)
					return &EKPublicKey{ECC: pk}, nil, warnings, nil
				}
			}
		}
	}

	// Priority 2: Parse from EKCert
	var certDER []byte
	if len(chain.EKCerts) > 0 {
		if d, err := decodeBase64OrErr(chain.EKCerts[0]); err == nil {
			certDER = d
		}
	}
	if certDER == nil && len(chain.EKNVCerts) > 0 {
		if d, err := decodeBase64OrErr(chain.EKNVCerts[0]); err == nil {
			certDER = d
		}
	}
	if certDER == nil && chain.NVIndexBlobs != nil {
		if b64, ok := chain.NVIndexBlobs["0x01c00002"]; ok {
			if d, err := decodeBase64OrErr(b64); err == nil {
				certDER = d
			}
		}
	}
	if certDER == nil {
		return nil, nil, warnings, fmt.Errorf("missing EK certificate and ek_pub")
	}

	ekCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, warnings, fmt.Errorf("failed to parse EK certificate: %w", err)
	}

	// Best-effort chain verification:
	// - Use client-provided intermediates (EICA certs)
	// - Use NV chain blobs if present (0x01c00100 often contains concatenated DERs)
	// - Auto-fetch missing intermediates from AIA URLs (restricted by allowlisted hosts), with caching
	intermediates := x509.NewCertPool()
	addIntermediates := func(certs []*x509.Certificate) {
		for _, c := range certs {
			if c != nil {
				intermediates.AddCert(c)
			}
		}
	}

	// From eica_certs (expected to be DER certs)
	for _, b64 := range chain.EICACerts {
		der, derr := decodeBase64OrErr(b64)
		if derr != nil {
			warnings = append(warnings, "Invalid eica_certs base64")
			continue
		}
		c, perr := x509.ParseCertificate(der)
		if perr != nil {
			warnings = append(warnings, "Failed to parse one eica cert as DER")
			continue
		}
		intermediates.AddCert(c)
	}

	// From nv_index_blobs chain range (concatenated DER)
	if chain.NVIndexBlobs != nil {
		for k, v := range chain.NVIndexBlobs {
			// Only try EK chain range here; EK cert indices are leafs.
			if strings.HasPrefix(strings.ToLower(k), "0x01c001") {
				der, derr := decodeBase64OrErr(v)
				if derr != nil {
					continue
				}
				certs, _ := splitConcatenatedDerCerts(der)
				addIntermediates(certs)
			}
		}
	}

	// From AIA URLs
	aiaCerts, aiaWarn := fetchAiaIssuerChain(ekCert, 6)
	warnings = append(warnings, aiaWarn...)

	// Separate AIA certs into roots (self-signed) and intermediates
	// Start with builtin TPM manufacturer root CAs
	roots := builtinTPMRootCAs()
	for _, c := range aiaCerts {
		if c != nil {
			if c.Issuer.String() == c.Subject.String() {
				if err := c.CheckSignatureFrom(c); err == nil {
					debugLog("extractEkPublicKey", "Adding self-signed root from AIA: %s", c.Subject.CommonName)
					roots.AddCert(c)
					continue
				}
			}
			intermediates.AddCert(c)
		}
	}

	// Also check if any EICA cert is a self-signed root
	for _, b64 := range chain.EICACerts {
		der, derr := decodeBase64OrErr(b64)
		if derr != nil {
			continue
		}
		c, perr := x509.ParseCertificate(der)
		if perr != nil {
			continue
		}
		if c.Issuer.String() == c.Subject.String() {
			if err := c.CheckSignatureFrom(c); err == nil {
				debugLog("extractEkPublicKey", "Adding self-signed root from EICA: %s", c.Subject.CommonName)
				roots.AddCert(c)
			}
		}
	}

	opts := x509.VerifyOptions{Intermediates: intermediates, Roots: roots}
	if _, verr := ekCert.Verify(opts); verr != nil {
		// Don't hard-fail here; in many dev envs roots are missing. We still can use EK pub for activation.
		warnings = append(warnings, fmt.Sprintf("EK certificate chain verify failed (continuing): %v", verr))
	} else {
		debugLog("extractEkPublicKey", "EK certificate chain verified successfully!")
	}

	pub := ekCert.PublicKey
	switch pk := pub.(type) {
	case *rsa.PublicKey:
		debugLog("extractEkPublicKey", "Using EK pub from certificate (RSA), bits=%d", pk.N.BitLen())
		return &EKPublicKey{RSA: pk}, ekCert, warnings, nil
	case *ecdsa.PublicKey:
		debugLog("extractEkPublicKey", "Using EK pub from certificate (ECC), curve=%s", pk.Curve.Params().Name)
		return &EKPublicKey{ECC: pk}, ekCert, warnings, nil
	default:
		return nil, ekCert, warnings, fmt.Errorf("EK public key type unsupported: %T", pub)
	}
}

// tryParseFirstEkCert attempts to parse the first available EK certificate (best-effort, for logging/verification)
func tryParseFirstEkCert(chain TPMCertificateChain) *x509.Certificate {
	tryParse := func(b64 string) *x509.Certificate {
		if b64 == "" {
			return nil
		}
		der, err := decodeBase64OrErr(b64)
		if err != nil {
			return nil
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil
		}
		return cert
	}
	for _, c := range chain.EKCerts {
		if cert := tryParse(c); cert != nil {
			return cert
		}
	}
	for _, c := range chain.EKNVCerts {
		if cert := tryParse(c); cert != nil {
			return cert
		}
	}
	if chain.NVIndexBlobs != nil {
		if b64, ok := chain.NVIndexBlobs["0x01c00002"]; ok {
			if cert := tryParse(b64); cert != nil {
				return cert
			}
		}
	}
	return nil
}

// parseBCryptRSAPublicBlob parses Windows BCRYPT_RSAPUBLIC_BLOB format
func parseBCryptRSAPublicBlob(blob []byte) *rsa.PublicKey {
	// BCRYPT_RSAKEY_BLOB structure:
	// ULONG Magic;       // 0x31415352 = "RSA1" for public key
	// ULONG BitLength;   // Key size in bits
	// ULONG cbPublicExp; // Size of public exponent in bytes
	// ULONG cbModulus;   // Size of modulus in bytes
	// ULONG cbPrime1;    // 0 for public key
	// ULONG cbPrime2;    // 0 for public key
	// BYTE PublicExponent[cbPublicExp];
	// BYTE Modulus[cbModulus];

	if len(blob) < 24 {
		return nil
	}

	magic := binary.LittleEndian.Uint32(blob[0:4])
	if magic != 0x31415352 { // "RSA1"
		return nil
	}

	bitLen := binary.LittleEndian.Uint32(blob[4:8])
	expSize := binary.LittleEndian.Uint32(blob[8:12])
	modSize := binary.LittleEndian.Uint32(blob[12:16])

	debugLog("parseBCryptRSA", "BitLength: %d, ExpSize: %d, ModSize: %d", bitLen, expSize, modSize)

	headerSize := uint32(24) // 6 * 4 bytes
	if uint32(len(blob)) < headerSize+expSize+modSize {
		return nil
	}

	expBytes := blob[headerSize : headerSize+expSize]
	modBytes := blob[headerSize+expSize : headerSize+expSize+modSize]

	exp := new(big.Int).SetBytes(expBytes)
	mod := new(big.Int).SetBytes(modBytes)

	return &rsa.PublicKey{
		N: mod,
		E: int(exp.Int64()),
	}
}
