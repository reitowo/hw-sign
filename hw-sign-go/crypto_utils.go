package main

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
)

// ============ Debug Logger ============

func debugLog(step string, format string, v ...interface{}) {
	message := fmt.Sprintf(format, v...)
	log.Printf("[DEBUG] %s: %s", step, message)
}

// ============ Random String Generation ============

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// ============ Public Key Parsing ============

func parsePublicKey(keyData string, keyType string) (interface{}, error) {
	debugLog("parsePublicKey", "Parsing %s key, length: %d", keyType, len(keyData))
	decoded, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	// Normalize key type to lowercase
	keyType = strings.ToLower(keyType)

	switch keyType {
	case string(KeyTypeEd25519):
		return parseEd25519PublicKey(decoded)

	case string(KeyTypeECDSA):
		return parseECDSAPublicKey(decoded)

	case string(KeyTypeRSAPKCS1), string(KeyTypeRSAPSS):
		return parseRSAPublicKey(decoded)

	case string(KeyTypeECDH):
		return parseECDHPublicKey(decoded)
	}

	return nil, errors.New("unsupported key type")
}

func parseEd25519PublicKey(decoded []byte) (interface{}, error) {
	if len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 key size")
	}
	return ed25519.PublicKey(decoded), nil
}

func parseECDSAPublicKey(decoded []byte) (interface{}, error) {
	// Try uncompressed point format first
	if len(decoded) == 65 && decoded[0] == 0x04 {
		return parseRawECDSAPublicKeyX962(decoded)
	}

	// Otherwise try PKIX format
	key, err := x509.ParsePKIXPublicKey(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA public key: %w", err)
	}

	if ecKey, ok := key.(*ecdsa.PublicKey); ok {
		return ecKey, nil
	}
	return nil, errors.New("key is not ECDSA")
}

func parseRSAPublicKey(decoded []byte) (interface{}, error) {
	key, err := x509.ParsePKIXPublicKey(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}
	if rsaKey, ok := key.(*rsa.PublicKey); ok {
		return rsaKey, nil
	}
	return nil, errors.New("key is not RSA")
}

func parseECDHPublicKey(decoded []byte) (interface{}, error) {
	curve := ecdh.P256()

	// Try to handle the key directly first
	pubKey, err := curve.NewPublicKey(decoded)
	if err == nil {
		return pubKey, nil
	}

	// Try uncompressed point format
	if len(decoded) == 65 && decoded[0] == 0x04 {
		x := new(big.Int).SetBytes(decoded[1:33])
		y := new(big.Int).SetBytes(decoded[33:65])

		if !elliptic.P256().IsOnCurve(x, y) {
			return nil, fmt.Errorf("point is not on P-256 curve")
		}

		rawKey := elliptic.Marshal(elliptic.P256(), x, y)
		return curve.NewPublicKey(rawKey)
	}

	// Try PKIX format
	key, err := x509.ParsePKIXPublicKey(decoded)
	if err == nil {
		if ecKey, ok := key.(*ecdsa.PublicKey); ok && ecKey.Curve == elliptic.P256() {
			rawKey := elliptic.Marshal(ecKey.Curve, ecKey.X, ecKey.Y)
			return curve.NewPublicKey(rawKey)
		}
	}

	return nil, fmt.Errorf("invalid or unsupported ECDH key format")
}

// Parse raw ECDSA public key in X9.62 uncompressed point format
func parseRawECDSAPublicKeyX962(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) != 65 || data[0] != 0x04 {
		return nil, fmt.Errorf("invalid EC public key format")
	}

	x := new(big.Int).SetBytes(data[1:33])
	y := new(big.Int).SetBytes(data[33:65])

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(), // Assuming P-256
		X:     x,
		Y:     y,
	}
	return pubKey, nil
}

// ============ Signature Verification ============

// Verify a signature using the appropriate algorithm based on key type
func verifySignature(publicKey interface{}, data []byte, signature []byte) bool {
	hash := sha256.Sum256(data)

	switch key := publicKey.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(key, hash[:], signature)

	case *ecdsa.PublicKey:
		// Try ASN.1 signature first
		if ecdsa.VerifyASN1(key, hash[:], signature) {
			return true
		}
		// Fallback to raw r||s format
		if len(signature) == 64 {
			r := new(big.Int).SetBytes(signature[:32])
			s := new(big.Int).SetBytes(signature[32:])
			return ecdsa.Verify(key, hash[:], r, s)
		}
		return false

	default:
		return false
	}
}

// Verify a signature using the appropriate algorithm based on key type
func verifyRsaSignature(pt string, publicKey interface{}, data []byte, signature []byte) bool {
	hash := sha256.Sum256(data)

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		switch pt {
		case "rsa-2048-pkcs1":
			err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature)
			return err == nil
		case "rsa-2048-pss":
			opts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA256,
			}
			err := rsa.VerifyPSS(key, crypto.SHA256, hash[:], signature, opts)
			return err == nil
		}
	}
	return false
}

// ============ ECDH Key Exchange ============

// Generate a new ECDH key pair
func generateECDHKeyPair() (*ecdh.PrivateKey, error) {
	curve := ecdh.P256()
	return curve.GenerateKey(rand.Reader)
}

// Compute shared secret from ECDH key exchange
func computeSharedSecret(privateKey *ecdh.PrivateKey, publicKey *ecdh.PublicKey) ([]byte, error) {
	debugLog("ECDH", "Computing shared secret between keys")
	sharedSecret, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}

	// Log for debugging
	log.Printf("HMAC debug - derived key hash: %s", base64.StdEncoding.EncodeToString(sharedSecret[:]))

	// The derived secret should be 32 bytes for P-256 curve
	return sharedSecret, nil
}

// ============ HMAC Functions ============

// Validate request with HMAC
func validateHMACRequest(symmetricKey []byte, data, sig string) error {
	debugLog("HMAC", "Validating HMAC for data (%d chars)", len(data))
	if sig == "" {
		return errors.New("missing HMAC signature")
	}

	// Log the input for debugging
	log.Printf("HMAC debug - data: %s, sig: %s", data, sig)

	// Compute HMAC using SHA-256
	mac := hmac.New(sha256.New, symmetricKey)
	mac.Write([]byte(data))
	expectedHMAC := mac.Sum(nil)
	expectedBase64 := base64.StdEncoding.EncodeToString(expectedHMAC)

	// Debug info
	log.Printf("HMAC debug - computed base64: %s", expectedBase64)

	// Decode the received signature
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("invalid HMAC format: %w", err)
	}

	// Compare both ways for debugging
	log.Printf("HMAC debug - bytes equal: %v", bytes.Equal(sigBytes, expectedHMAC))
	log.Printf("HMAC debug - base64 equal: %v", sig == expectedBase64)

	// Compare the HMACs
	if !bytes.Equal(sigBytes, expectedHMAC) {
		// Return more information for debugging
		return fmt.Errorf("HMAC mismatch: expected %s, got %s", expectedBase64, sig)
	}

	return nil
}

// ============ Base64 Helpers ============

func decodeBase64OrErr(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}
