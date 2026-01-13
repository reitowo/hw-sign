package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Parse PCP IdBinding blob to extract the AIK public area blob (TPMT_PUBLIC bytes) and compute AIK Name.
// The format follows PCPTool GenerateActivation20 expectations:
//   - UINT16 size + aikPub
//   - UINT16 size + creationData
//   - UINT16 size + attest
//   - UINT16 signatureScheme
//   - UINT16 signatureHash
//   - UINT16 size + signature
func parseIdBindingAndComputeAikName(idBinding []byte) (aikPub []byte, aikName []byte, err error) {
	rdU16 := func(buf []byte, off *int) (uint16, error) {
		if *off+2 > len(buf) {
			return 0, errors.New("buffer underflow")
		}
		v := binary.BigEndian.Uint16(buf[*off : *off+2])
		*off += 2
		return v, nil
	}
	rdBytes := func(buf []byte, off *int, n int) ([]byte, error) {
		if *off+n > len(buf) {
			return nil, errors.New("buffer underflow")
		}
		out := buf[*off : *off+n]
		*off += n
		return out, nil
	}

	off := 0
	cbAikPub, err := rdU16(idBinding, &off)
	if err != nil {
		return nil, nil, err
	}
	aikPub, err = rdBytes(idBinding, &off, int(cbAikPub))
	if err != nil {
		return nil, nil, err
	}

	// Skip creationData + attest + signature fields; we only need AIK pub for Name.
	cbCreation, err := rdU16(idBinding, &off)
	if err != nil {
		return nil, nil, err
	}
	_, err = rdBytes(idBinding, &off, int(cbCreation))
	if err != nil {
		return nil, nil, err
	}
	cbAttest, err := rdU16(idBinding, &off)
	if err != nil {
		return nil, nil, err
	}
	_, err = rdBytes(idBinding, &off, int(cbAttest))
	if err != nil {
		return nil, nil, err
	}
	// signatureScheme + signatureHash
	_, err = rdU16(idBinding, &off)
	if err != nil {
		return nil, nil, err
	}
	_, err = rdU16(idBinding, &off)
	if err != nil {
		return nil, nil, err
	}
	cbSig, err := rdU16(idBinding, &off)
	if err != nil {
		return nil, nil, err
	}
	_, err = rdBytes(idBinding, &off, int(cbSig))
	if err != nil {
		return nil, nil, err
	}

	if len(aikPub) < 4 {
		return nil, nil, errors.New("aikPub too small")
	}
	// AIK pub is TPMT_PUBLIC-like:
	// objectType (u16) | nameAlg (u16) | ... rest
	nameAlg := binary.BigEndian.Uint16(aikPub[2:4])
	var digest []byte
	switch nameAlg {
	case 0x0004: // TPM_ALG_SHA1
		return nil, nil, fmt.Errorf("unsupported AIK nameAlg SHA1 (0x0004) in this server implementation")
	case 0x000B: // TPM_ALG_SHA256
		sum := sha256.Sum256(aikPub)
		digest = sum[:]
	default:
		return nil, nil, fmt.Errorf("unsupported AIK nameAlg: 0x%04x", nameAlg)
	}
	aikName = make([]byte, 2+len(digest))
	binary.BigEndian.PutUint16(aikName[0:2], nameAlg)
	copy(aikName[2:], digest)
	return aikPub, aikName, nil
}

// TPM2.0 KDFa (HMAC-based) with SHA256.
func kdfaSha256(key []byte, label string, contextU []byte, contextV []byte, bits uint32) ([]byte, error) {
	if bits%8 != 0 {
		return nil, errors.New("bits must be multiple of 8")
	}
	bytesNeeded := int(bits / 8)
	out := make([]byte, 0, bytesNeeded)

	counter := uint32(1)
	for len(out) < bytesNeeded {
		mac := hmac.New(sha256.New, key)
		// counter (big-endian)
		var cbuf [4]byte
		binary.BigEndian.PutUint32(cbuf[:], counter)
		mac.Write(cbuf[:])
		// label + 0x00
		mac.Write([]byte(label))
		mac.Write([]byte{0x00})
		// contextU || contextV
		if len(contextU) > 0 {
			mac.Write(contextU)
		}
		if len(contextV) > 0 {
			mac.Write(contextV)
		}
		// bits (big-endian)
		var bbuf [4]byte
		binary.BigEndian.PutUint32(bbuf[:], bits)
		mac.Write(bbuf[:])
		block := mac.Sum(nil)

		need := bytesNeeded - len(out)
		if need >= len(block) {
			out = append(out, block...)
		} else {
			out = append(out, block[:need]...)
		}
		counter++
	}
	return out, nil
}

// buildCredentialBlob builds the TPM2B_ID_OBJECT portion (common for RSA and ECC)
func buildCredentialBlob(seed []byte, aikName []byte, secret []byte) ([]byte, error) {
	// symKey = KDFa(seed, "STORAGE", aikName, NULL, 128)
	symKey, err := kdfaSha256(seed, "STORAGE", aikName, nil, 128)
	if err != nil {
		return nil, err
	}
	// hmacKey = KDFa(seed, "INTEGRITY", NULL, NULL, 256)
	hmacKey, err := kdfaSha256(seed, "INTEGRITY", nil, nil, 256)
	if err != nil {
		return nil, err
	}

	// encIdentity = AES-128-CFB(symKey, iv=0) over TPM2B_DIGEST (size||secret)
	encIdentity := make([]byte, 2+len(secret))
	binary.BigEndian.PutUint16(encIdentity[0:2], uint16(len(secret)))
	copy(encIdentity[2:], secret)
	{
		block, berr := aes.NewCipher(symKey)
		if berr != nil {
			return nil, berr
		}
		iv := make([]byte, 16) // all zero
		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(encIdentity, encIdentity)
	}

	// outerHMAC = HMAC(hmacKey, encIdentity || aikName)
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(encIdentity)
	mac.Write(aikName)
	outer := mac.Sum(nil) // 32 bytes

	// Build TPM2B_ID_OBJECT:
	// [sizeTotal][outerSize=32][outer][credCipher]
	credBodyLen := 2 + 32 + len(encIdentity)
	cred := make([]byte, 2+credBodyLen)
	binary.BigEndian.PutUint16(cred[0:2], uint16(credBodyLen))
	binary.BigEndian.PutUint16(cred[2:4], 32)
	copy(cred[4:4+32], outer)
	copy(cred[4+32:], encIdentity)

	return cred, nil
}

// kdfeSha256 implements TPM 2.0 KDFe (ECDH key derivation) per TCG spec
// KDFe(hashAlg, Z, label, PartyUInfo, PartyVInfo, bits)
func kdfeSha256(z []byte, label string, partyU []byte, partyV []byte, bits uint32) ([]byte, error) {
	bytesNeeded := int(bits / 8)
	out := make([]byte, 0, bytesNeeded)

	counter := uint32(1)
	for len(out) < bytesNeeded {
		h := sha256.New()
		// counter (big-endian)
		var cbuf [4]byte
		binary.BigEndian.PutUint32(cbuf[:], counter)
		h.Write(cbuf[:])
		// Z (shared secret)
		h.Write(z)
		// label + 0x00
		h.Write([]byte(label))
		h.Write([]byte{0x00})
		// PartyU
		if len(partyU) > 0 {
			h.Write(partyU)
		}
		// PartyV
		if len(partyV) > 0 {
			h.Write(partyV)
		}
		block := h.Sum(nil)

		need := bytesNeeded - len(out)
		if need >= len(block) {
			out = append(out, block...)
		} else {
			out = append(out, block[:need]...)
		}
		counter++
	}
	return out, nil
}

// makeActivationBlobRSA creates activation blob for RSA EK
func makeActivationBlobRSA(ekPub *rsa.PublicKey, aikName []byte, secret []byte) ([]byte, error) {
	// Seed: 16 bytes
	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}

	cred, err := buildCredentialBlob(seed, aikName, secret)
	if err != nil {
		return nil, err
	}

	// EncryptedSecret: RSA-OAEP(SHA256, label="IDENTITY\0") over seed
	label := append([]byte("IDENTITY"), 0x00)
	encSeed, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, ekPub, seed, label)
	if err != nil {
		return nil, fmt.Errorf("rsa oaep encrypt failed: %w", err)
	}
	secret2b := make([]byte, 2+len(encSeed))
	binary.BigEndian.PutUint16(secret2b[0:2], uint16(len(encSeed)))
	copy(secret2b[2:], encSeed)

	debugLog("makeActivationBlobRSA", "Created RSA activation blob: cred=%d, encSeed=%d", len(cred), len(encSeed))
	return append(cred, secret2b...), nil
}

// makeActivationBlobECC creates activation blob for ECC EK (P-256/P-384/P-521)
// Uses ECDH + KDFe per TCG TPM 2.0 spec
func makeActivationBlobECC(ekPub *ecdsa.PublicKey, aikName []byte, secret []byte) ([]byte, error) {
	curve := ekPub.Curve

	// Generate ephemeral ECDH key pair
	ephPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Compute shared secret Z = ECDH(ephPriv, ekPub) - just X coordinate
	zX, _ := curve.ScalarMult(ekPub.X, ekPub.Y, ephPriv.D.Bytes())
	z := zX.Bytes()
	// Pad Z to curve byte size
	byteSize := (curve.Params().BitSize + 7) / 8
	if len(z) < byteSize {
		padded := make([]byte, byteSize)
		copy(padded[byteSize-len(z):], z)
		z = padded
	}

	// PartyU = ephemeral public X coordinate (big-endian, padded)
	partyU := ephPriv.PublicKey.X.Bytes()
	if len(partyU) < byteSize {
		padded := make([]byte, byteSize)
		copy(padded[byteSize-len(partyU):], partyU)
		partyU = padded
	}

	// PartyV = EK public X coordinate (big-endian, padded)
	partyV := ekPub.X.Bytes()
	if len(partyV) < byteSize {
		padded := make([]byte, byteSize)
		copy(padded[byteSize-len(partyV):], partyV)
		partyV = padded
	}

	// Derive seed using KDFe: seed = KDFe(SHA256, Z, "IDENTITY", partyU, partyV, 128)
	seed, err := kdfeSha256(z, "IDENTITY", partyU, partyV, 128)
	if err != nil {
		return nil, err
	}

	cred, err := buildCredentialBlob(seed, aikName, secret)
	if err != nil {
		return nil, err
	}

	// EncryptedSecret for ECC: TPM2B_ECC_POINT (ephemeral public key)
	// Format: size(u16) || X size(u16) || X bytes || Y size(u16) || Y bytes
	ephX := ephPriv.PublicKey.X.Bytes()
	ephY := ephPriv.PublicKey.Y.Bytes()
	// Pad to curve byte size
	if len(ephX) < byteSize {
		padded := make([]byte, byteSize)
		copy(padded[byteSize-len(ephX):], ephX)
		ephX = padded
	}
	if len(ephY) < byteSize {
		padded := make([]byte, byteSize)
		copy(padded[byteSize-len(ephY):], ephY)
		ephY = padded
	}

	// TPM2B_ECC_POINT: size(u16) || TPMS_ECC_POINT { TPM2B_ECC_PARAMETER x, TPM2B_ECC_PARAMETER y }
	pointBodyLen := 2 + len(ephX) + 2 + len(ephY)
	secret2b := make([]byte, 2+pointBodyLen)
	binary.BigEndian.PutUint16(secret2b[0:2], uint16(pointBodyLen))
	binary.BigEndian.PutUint16(secret2b[2:4], uint16(len(ephX)))
	copy(secret2b[4:4+len(ephX)], ephX)
	binary.BigEndian.PutUint16(secret2b[4+len(ephX):6+len(ephX)], uint16(len(ephY)))
	copy(secret2b[6+len(ephX):], ephY)

	debugLog("makeActivationBlobECC", "Created ECC activation blob: cred=%d, point=%d, curve=%s", len(cred), len(secret2b), curve.Params().Name)
	return append(cred, secret2b...), nil
}

// makeActivationBlob creates activation blob for either RSA or ECC EK
func makeActivationBlob(ekPub *EKPublicKey, aikName []byte, secret []byte) ([]byte, error) {
	if ekPub == nil {
		return nil, errors.New("ekPub is nil")
	}
	if len(aikName) != 2+32 {
		return nil, fmt.Errorf("unexpected aikName size: %d", len(aikName))
	}
	if len(secret) == 0 || len(secret) > 32 {
		return nil, fmt.Errorf("invalid secret length: %d", len(secret))
	}

	if ekPub.RSA != nil {
		return makeActivationBlobRSA(ekPub.RSA, aikName, secret)
	}
	if ekPub.ECC != nil {
		return makeActivationBlobECC(ekPub.ECC, aikName, secret)
	}
	return nil, errors.New("no valid EK public key")
}
