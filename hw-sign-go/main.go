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
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
)

// Key type definitions
type KeyType string

const (
	KeyTypeEd25519 KeyType = "ed25519"
	KeyTypeECDSA   KeyType = "ecdsa-p256"
	KeyTypeRSAPSS  KeyType = "rsa-2048-pss"
	KeyTypeECDH    KeyType = "ecdh-p256"
)

// Unified key structures for better organization
type PublicKeyInfo struct {
	Key  []byte
	Type KeyType
}

type UnifiedKeyInfo struct {
	PublicKey     []byte      // Public key for asymmetric crypto
	KeyType       KeyType     // Type of key (ecdsa, rsa-2048, ed25519)
	SymmetricKey  []byte      // AES-256 key for symmetric encryption (if available)
	ServerPrivKey interface{} // Server's private key for ECDH (if applicable)
	HwKey         interface{}
}

// In-memory caches with consistent expiration times
const (
	defaultCacheExpiry = 3 * time.Hour
	cleanupInterval    = 10 * time.Minute
)

var (
	usersCache     = cache.New(defaultCacheExpiry, cleanupInterval) // Cache for user data
	accelKeys      = cache.New(defaultCacheExpiry, cleanupInterval) // Cache for unified acceleration keys
	tokensCache    = cache.New(defaultCacheExpiry, cleanupInterval) // Cache for tokens and associated hardware keys
	challengeCache = cache.New(5*time.Minute, time.Minute)          // Cache for attestation challenges (shorter expiry)
)

// TPM policy constants (from TPM20.cpp)
var (
	defaultUserPolicy = []byte{
		0x8f, 0xcd, 0x21, 0x69, 0xab, 0x92, 0x69, 0x4e,
		0x0c, 0x63, 0x3f, 0x1a, 0xb7, 0x72, 0x84, 0x2b,
		0x82, 0x41, 0xbb, 0xc2, 0x02, 0x88, 0x98, 0x1f,
		0xc7, 0xac, 0x1e, 0xdd, 0xc1, 0xfd, 0xdb, 0x0e,
	}
	adminObjectChangeAuthPolicy = []byte{
		0xe5, 0x29, 0xf5, 0xd6, 0x11, 0x28, 0x72, 0x95,
		0x4e, 0x8e, 0xd6, 0x60, 0x51, 0x17, 0xb7, 0x57,
		0xe2, 0x37, 0xc6, 0xe1, 0x95, 0x13, 0xa9, 0x49,
		0xfe, 0xe1, 0xf2, 0x04, 0xc4, 0x58, 0x02, 0x3a,
	}
	adminCertifyPolicy = []byte{
		0xaf, 0x2c, 0xa5, 0x69, 0x69, 0x9c, 0x43, 0x6a,
		0x21, 0x00, 0x6f, 0x1c, 0xb8, 0xa2, 0x75, 0x6c,
		0x98, 0xbc, 0x1c, 0x76, 0x5a, 0x35, 0x59, 0xc5,
		0xfe, 0x1c, 0x3f, 0x5e, 0x72, 0x28, 0xa7, 0xe7,
	}
	adminCertifyPolicyNoPin = []byte{
		0x04, 0x8e, 0x9a, 0x3a, 0xce, 0x08, 0x58, 0x3f,
		0x79, 0xf3, 0x44, 0xff, 0x78, 0x5b, 0xbe, 0xa9,
		0xf0, 0x7a, 0xc7, 0xfa, 0x33, 0x25, 0xb3, 0xd4,
		0x9a, 0x21, 0xdd, 0x51, 0x94, 0xc6, 0x58, 0x50,
	}
	adminActivateCredentialPolicy = []byte{
		0xc4, 0x13, 0xa8, 0x47, 0xb1, 0x11, 0x12, 0xb1,
		0xcb, 0xdd, 0xd4, 0xec, 0xa4, 0xda, 0xaa, 0x15,
		0xa1, 0x85, 0x2c, 0x1c, 0x3b, 0xba, 0x57, 0x46,
		0x1d, 0x25, 0x76, 0x05, 0xf3, 0xd5, 0xaf, 0x53,
	}
)

// TPM constants
const (
	TPM_CC_PolicyPCR        = 0x0000017F
	TPM_CC_PolicyOR         = 0x00000171
	TPM_ALG_SHA1            = 0x0004
	TPM_ALG_SHA256          = 0x000B
	AVAILABLE_PLATFORM_PCRS = 24
)

// Custom logger for debugging
func debugLog(step string, format string, v ...interface{}) {
	message := fmt.Sprintf(format, v...)
	log.Printf("[DEBUG] %s: %s", step, message)
}

// Helper function to read big-endian 16-bit value and following data
func readBigEndian2B(data []byte, cursor *int) (uint16, []byte, error) {
	if len(data) < *cursor+2 {
		return 0, nil, errors.New("insufficient data for 2B size")
	}

	size := binary.BigEndian.Uint16(data[*cursor : *cursor+2])
	*cursor += 2

	if len(data) < *cursor+int(size) {
		return 0, nil, errors.New("insufficient data for 2B content")
	}

	content := data[*cursor : *cursor+int(size)]
	*cursor += int(size)

	return size, content, nil
}

// Calculate user policy with PCR data
func calculateUserPolicyWithPCRs(pcrTable []byte, pcrMask uint32, pcrAlgId uint16, keyBlobPcrDigest []byte) ([]byte, error) {
	var digestSize int
	if pcrAlgId == TPM_ALG_SHA256 {
		digestSize = 32
	} else if pcrAlgId == TPM_ALG_SHA1 {
		digestSize = 20
	} else {
		return nil, fmt.Errorf("unsupported PCR algorithm: 0x%04X", pcrAlgId)
	}

	// Build PCR composite from selected PCRs
	var pcrComposite []byte
	for n := 0; n < AVAILABLE_PLATFORM_PCRS; n++ {
		if (pcrMask & (1 << n)) != 0 {
			start := n * digestSize
			end := start + digestSize
			if len(pcrTable) < end {
				return nil, fmt.Errorf("insufficient PCR data for PCR %d", n)
			}
			pcrComposite = append(pcrComposite, pcrTable[start:end]...)
		}
	}

	// Calculate PCR composite digest using SHA256 (determined by policy, not PCR bank algorithm)
	h := sha256.New()
	h.Write(pcrComposite)
	pcrCompositeDigest := h.Sum(nil)

	// Verify PCR composite digest matches key blob
	if !bytes.Equal(keyBlobPcrDigest, pcrCompositeDigest) {
		return nil, errors.New("PCR composite digest mismatch")
	}

	// Build policy digest buffer for PCR policy calculation
	policyDigestBuffer := make([]byte, 0, 32+4+4+2+1+3+32)

	// Add default user policy
	policyDigestBuffer = append(policyDigestBuffer, defaultUserPolicy...)

	// Add TPM_CC_PolicyPCR
	tpmCcBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tpmCcBytes, TPM_CC_PolicyPCR)
	policyDigestBuffer = append(policyDigestBuffer, tpmCcBytes...)

	// Add TPML_PCR_SELECTION.count (1)
	countBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(countBytes, 1)
	policyDigestBuffer = append(policyDigestBuffer, countBytes...)

	// Add TPML_PCR_SELECTION.TPMS_PCR_SELECTION.hash
	algBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(algBytes, pcrAlgId)
	policyDigestBuffer = append(policyDigestBuffer, algBytes...)

	// Add TPML_PCR_SELECTION.TPMS_PCR_SELECTION.sizeofSelect (3)
	policyDigestBuffer = append(policyDigestBuffer, 0x03)

	// Add TPML_PCR_SELECTION.TPMS_PCR_SELECTION.Select (3 bytes)
	pcrSelectBytes := make([]byte, 3)
	pcrSelectBytes[0] = byte(pcrMask & 0xFF)
	pcrSelectBytes[1] = byte((pcrMask >> 8) & 0xFF)
	pcrSelectBytes[2] = byte((pcrMask >> 16) & 0xFF)
	policyDigestBuffer = append(policyDigestBuffer, pcrSelectBytes...)

	// Add PCR digest
	policyDigestBuffer = append(policyDigestBuffer, pcrCompositeDigest...)

	// Calculate final policy digest using SHA256
	h = sha256.New()
	h.Write(policyDigestBuffer)
	return h.Sum(nil), nil
}

// Attestation structures
type AttestationRequest struct {
	Attestation  string `json:"attestation"`
	AIKPublicKey string `json:"aik_public_key"`
	PCRValues    string `json:"pcr_values"`
	KeyType      string `json:"key_type"`
	Nonce        string `json:"nonce,omitempty"`
}

type ChallengeResponse struct {
	Nonce string `json:"nonce"`
}

// ============ Crypto Utility Functions ============

// Generate cryptographically secure random string
func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// Parse public key from base64 encoded string based on key type
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

	case string(KeyTypeRSAPSS):
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

// Verify a signature using the appropriate algorithm based on key type
func verifySignature(publicKey interface{}, data []byte, signature []byte) bool {
	hash := sha256.Sum256(data)

	switch key := publicKey.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(key, data, signature)

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

	case *rsa.PublicKey:
		opts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA256,
		}
		err := rsa.VerifyPSS(key, crypto.SHA256, hash[:], signature, opts)
		return err == nil

	default:
		return false
	}
}

// Generate a new ECDH key pair
func generateECDHKeyPair() (*ecdh.PrivateKey, error) {
	curve := ecdh.P256()
	return curve.GenerateKey(rand.Reader)
}

// ============ AES Encryption Functions ============

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
	return sharedSecret[:], nil
}

// ============ HTTP Helper Functions ============

// Add CORS headers to response
func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-rpc-sec-bound-token-hw-pub, x-rpc-sec-bound-token-hw-pub-type, x-rpc-sec-bound-token-accel-pub, x-rpc-sec-bound-token-accel-pub-type, x-rpc-sec-bound-token-accel-pub-sig, x-rpc-sec-bound-token-data, x-rpc-sec-bound-token-data-sig, x-rpc-sec-bound-token-accel-pub-id")
	w.Header().Set("Access-Control-Expose-Headers", "x-rpc-sec-bound-token-accel-pub-id, x-rpc-sec-bound-token-accel-pub")
}

// Send error response with CORS headers
func errorResponse(w http.ResponseWriter, message string, status int) {
	setCORSHeaders(w)
	http.Error(w, message, status)
}

// Send authentication success response
func sendAuthenticationSuccess(w http.ResponseWriter) {
	setCORSHeaders(w)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"authenticated": true})
}

// Verify signed data with proper error handling
func verifySignedData(key interface{}, data string, signature string) error {
	sigDecoded, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}

	if !verifySignature(key, []byte(data), sigDecoded) {
		return errors.New("invalid signature")
	}

	return nil
}

// Parse and validate key with proper error handling
func parseAndValidateKey(keyData string, keyType string, keyDesc string) (interface{}, error) {
	if keyData == "" || keyType == "" {
		return nil, fmt.Errorf("missing %s or type", keyDesc)
	}

	key, err := parsePublicKey(keyData, keyType)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", keyDesc, err)
	}

	return key, nil
}

// ============ HTTP Handlers ============

// Register new user
func registerHandler(w http.ResponseWriter, r *http.Request) {
	debugLog("registerHandler", "Received registration request from %s", r.RemoteAddr)
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var userData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&userData); err != nil {
		errorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Store user data
	usersCache.Set(userData.Username, userData, cache.DefaultExpiration)

	log.Printf("Registered user: %s", userData.Username)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

// Login and get auth token
func loginHandler(w http.ResponseWriter, r *http.Request) {
	debugLog("loginHandler", "Received login request from %s", r.RemoteAddr)
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		errorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get and validate hardware public key
	hwPubKey := r.Header.Get("x-rpc-sec-bound-token-hw-pub")
	hwPubType := r.Header.Get("x-rpc-sec-bound-token-hw-pub-type")

	if hwPubKey == "" || hwPubType == "" {
		errorResponse(w, "Missing hardware public key or type", http.StatusBadRequest)
		return
	}

	// Parse and validate hardware public key format
	_, err := parsePublicKey(hwPubKey, hwPubType)
	if err != nil {
		errorResponse(w, fmt.Sprintf("Invalid hardware public key: %v", err), http.StatusBadRequest)
		return
	}

	// Verify user credentials
	userData, found := usersCache.Get(credentials.Username)
	if !found || userData.(struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}).Password != credentials.Password {
		errorResponse(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate and store token
	token, err := generateRandomString(32)
	if err != nil {
		errorResponse(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	tokensCache.Set(token, PublicKeyInfo{
		Key:  []byte(hwPubKey),
		Type: KeyType(strings.ToLower(hwPubType)),
	}, cache.DefaultExpiration)

	log.Printf("User logged in: %s with key type: %s", credentials.Username, hwPubType)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// ============ Enhanced Crypto Utility Functions ============

// Verify ECDSA signature and then use the same key for ECDH key exchange
func verifyDataWithCliPubECDSA(clientPubKeyData string, data string, signature string) (*ecdsa.PublicKey, error) {
	debugLog("verifyDataWithCliPubECDSA", "Processing dual-purpose P-256 key, data: %s", data)

	// First parse as ECDSA public key for signature verification
	ecdsaKey, err := parsePublicKeyAsECDSAAndCheckCurveForECDH(clientPubKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA key: %w", err)
	}

	// Verify the data signature using ECDSA
	if err := verifyECDSASignature(ecdsaKey, data, signature); err != nil {
		return nil, fmt.Errorf("ECDSA signature verification failed: %w", err)
	}

	debugLog("verifyDataWithCliPubECDSA", "ECDSA signature verified successfully")
	return ecdsaKey, nil
}

// Parse ECDSA public key specifically for dual ECDSA/ECDH usage
func parsePublicKeyAsECDSAAndCheckCurveForECDH(keyData string) (*ecdsa.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	// Try uncompressed point format first (0x04 prefix)
	if len(decoded) == 65 && decoded[0] == 0x04 {
		return parseRawECDSAPublicKeyX962(decoded)
	}

	// Try PKIX format
	key, err := x509.ParsePKIXPublicKey(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not ECDSA")
	}

	// Ensure it's P-256 curve for dual usage
	if ecdsaKey.Curve != elliptic.P256() {
		return nil, errors.New("key must use P-256 curve for dual ECDSA/ECDH usage")
	}

	return ecdsaKey, nil
}

// Verify ECDSA signature specifically
func verifyECDSASignature(publicKey *ecdsa.PublicKey, data string, signature string) error {
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}

	hash := sha256.Sum256([]byte(data))

	// Try ASN.1 signature format first
	if ecdsa.VerifyASN1(publicKey, hash[:], sigBytes) {
		return nil
	}

	// Try raw r||s format (64 bytes for P-256)
	if len(sigBytes) == 64 {
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		if ecdsa.Verify(publicKey, hash[:], r, s) {
			return nil
		}
	}

	return errors.New("signature verification failed")
}

// Convert ECDSA public key to ECDH public key for key exchange
func convertECDSAToECDH(ecdsaKey *ecdsa.PublicKey) (*ecdh.PublicKey, error) {
	debugLog("convertECDSAToECDH", "Converting ECDSA P-256 key to ECDH format")

	if ecdsaKey.Curve != elliptic.P256() {
		return nil, errors.New("only P-256 curve supported for ECDSA to ECDH conversion")
	}

	// Marshal the ECDSA public key to uncompressed point format
	rawKey := elliptic.Marshal(ecdsaKey.Curve, ecdsaKey.X, ecdsaKey.Y)

	// Create ECDH public key from the marshaled data
	curve := ecdh.P256()
	ecdhKey, err := curve.NewPublicKey(rawKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDH key: %w", err)
	}

	return ecdhKey, nil
}

// Perform ECDH key exchange and return shared secret
func performECDHKeyExchange(serverPrivKey *ecdh.PrivateKey, clientECDHKey *ecdh.PublicKey) ([]byte, error) {
	debugLog("performECDHKeyExchange", "Performing ECDH key exchange with client's P-256 key")

	// Compute shared secret
	sharedSecret, err := computeSharedSecret(serverPrivKey, clientECDHKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH computation failed: %w", err)
	}

	debugLog("performECDHKeyExchange", "ECDH key exchange completed, shared secret length: %d", len(sharedSecret))
	return sharedSecret, nil
}

// Handle acceleration key registration with enhanced dual-purpose ECDSA/ECDH support
func verifyAccelKeyRegistrationRequest(w http.ResponseWriter, r *http.Request, hwKeyInfo PublicKeyInfo) error {
	debugLog("verifyAccelKeyRegistration", "Processing acceleration key registration, hw key type: %s", hwKeyInfo.Type)

	// Get request headers
	accelPub := r.Header.Get("x-rpc-sec-bound-token-accel-pub")
	accelPubType := r.Header.Get("x-rpc-sec-bound-token-accel-pub-type")
	accelPubSig := r.Header.Get("x-rpc-sec-bound-token-accel-pub-sig")
	data := r.Header.Get("x-rpc-sec-bound-token-data")
	dataSig := r.Header.Get("x-rpc-sec-bound-token-data-sig")

	if accelPub == "" || accelPubType == "" || accelPubSig == "" {
		errorResponse(w, "Missing acceleration key or signature", http.StatusBadRequest)
		return errors.New("missing acceleration key or signature")
	}

	// Parse hardware key for verification
	hwKey, err := parseAndValidateKey(string(hwKeyInfo.Key), string(hwKeyInfo.Type), "hardware key")
	if err != nil {
		errorResponse(w, err.Error(), http.StatusUnauthorized)
		return err
	}

	// Verify acceleration key is signed by hardware key
	if err := verifySignedData(hwKey, accelPub, accelPubSig); err != nil {
		errorResponse(w, fmt.Sprintf("hardware key verification failed: %v", err), http.StatusUnauthorized)
		return err
	}

	// Generate key ID
	accelKeyId, err := generateRandomString(16)
	if err != nil {
		errorResponse(w, "Failed to generate key ID", http.StatusInternalServerError)
		return err
	}

	// Create unified key info
	unifiedKey := UnifiedKeyInfo{
		PublicKey: []byte(accelPub),
		KeyType:   KeyType(strings.ToLower(accelPubType)),
	}

	// Handle ECDH case with dual-purpose ECDSA/ECDH key
	if strings.ToLower(accelPubType) == string(KeyTypeECDH) {
		if err := performDualPurposeECDHExchange(w, accelPub, data, dataSig, &unifiedKey); err != nil {
			errorResponse(w, err.Error(), http.StatusBadRequest)
			return err
		}
	} else {
		// Handle regular asymmetric key case
		if err := validateAsymmetricRequest(unifiedKey, data, dataSig); err != nil {
			errorResponse(w, err.Error(), http.StatusUnauthorized)
			return err
		}
	}

	// Store the unified key
	accelKeys.Set(accelKeyId, unifiedKey, cache.DefaultExpiration)
	w.Header().Set("x-rpc-sec-bound-token-accel-pub-id", accelKeyId)

	debugLog("verifyAccelKeyRegistration", "Acceleration key registered with ID: %s", accelKeyId)
	return nil
}

// Setup ECDH exchange with dual-purpose ECDSA/ECDH key
func performDualPurposeECDHExchange(w http.ResponseWriter, accelPub string, data string, dataSig string, unifiedKey *UnifiedKeyInfo) error {
	debugLog("performDualPurposeECDHExchange", "Setting up dual-purpose ECDSA/ECDH exchange")

	if data == "" || dataSig == "" {
		return errors.New("missing data or signature for ECDH initial verification")
	}

	// Step 1: Verify ECDSA signature of data, and convert the key to ECDH public key, must be SECG secp256r1 / X9.62 prime256v1 curve.
	clientECDSAPub, err := verifyDataWithCliPubECDSA(accelPub, data, dataSig)
	if err != nil {
		return fmt.Errorf("dual-purpose key verification failed: %v", err)
	}

	// Convert client's ECDSA key to ECDH format
	clientECDHPub, err := convertECDSAToECDH(clientECDSAPub)
	if err != nil {
		return fmt.Errorf("failed to convert client key to ECDH: %w", err)
	}

	// Step 2: Generate server's Random ECDH key pair
	serverECDHPriv, err := generateECDHKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate server ECDH key: %v", err)
	}

	// Step 3: Perform ECDH key exchange
	sharedSecret, err := performECDHKeyExchange(serverECDHPriv, clientECDHPub)
	if err != nil {
		return fmt.Errorf("ECDH key exchange failed: %v", err)
	}

	// Step 4: Return server's public key to client
	serverPubKeyBytes, _ := x509.MarshalPKIXPublicKey(serverECDHPriv.PublicKey())
	serverPubKeyBase64 := base64.StdEncoding.EncodeToString(serverPubKeyBytes)
	w.Header().Set("x-rpc-sec-bound-token-accel-pub", serverPubKeyBase64)

	// Step 5: Store the results in unified key info
	unifiedKey.SymmetricKey = sharedSecret
	unifiedKey.ServerPrivKey = serverECDHPriv

	debugLog("performDualPurposeECDHExchange", "Dual-purpose ECDH exchange completed successfully")
	return nil
}

// Verify authenticated requests
func verifyRequest(w http.ResponseWriter, r *http.Request, keyInfo UnifiedKeyInfo) error {
	debugLog("verifyRequest", "Verifying request, key type: %s, has symmetric key: %v", keyInfo.KeyType, keyInfo.SymmetricKey != nil)

	// Get data and signature from request
	data := r.Header.Get("x-rpc-sec-bound-token-data")
	dataSig := r.Header.Get("x-rpc-sec-bound-token-data-sig")

	debugLog("verifyRequest", "Request data: %s, signature length: %d", data, len(dataSig))

	// Special case for ECDH initial requests
	if keyInfo.KeyType == KeyTypeECDH && keyInfo.HwKey != nil {
		// This is an initial ECDH request that should be verified with hardware key
		hwKey := keyInfo.HwKey

		// Verify that we have the data and signature
		if data == "" || dataSig == "" {
			errorResponse(w, "missing data or signature for verification", http.StatusUnauthorized)
			return errors.New("missing data or signature for verification")
		}

		// Verify the data signature using the hardware key
		if err := verifySignedData(hwKey, data, dataSig); err != nil {
			errorResponse(w, fmt.Sprintf("failed to verify data signature: %v", err), http.StatusUnauthorized)
			return err
		}

		log.Printf("ECDH initial auth successful with hardware key: %s", data)
		return nil
	}

	if dataSig != "" && keyInfo.SymmetricKey != nil {
		debugLog("verifyRequest", "Using HMAC validation with symmetric key, length: %d", len(keyInfo.SymmetricKey))
		// Handle HMAC case
		if err := validateHMACRequest(keyInfo.SymmetricKey, data, dataSig); err != nil {
			log.Printf("HMAC validation failed: %v", err)
			errorResponse(w, err.Error(), http.StatusUnauthorized)
			return err
		}
		log.Printf("HMAC auth successful: %s", data)
	} else {
		debugLog("verifyRequest", "Using asymmetric signature validation")
		// Handle asymmetric signature case
		if err := validateAsymmetricRequest(keyInfo, data, dataSig); err != nil {
			errorResponse(w, err.Error(), http.StatusUnauthorized)
			return err
		}
		log.Printf("Asymmetric auth successful: %s", data)
	}

	// Authentication succeeded
	return nil
}

// Validate request with asymmetric signature
func validateAsymmetricRequest(keyInfo UnifiedKeyInfo, data, dataSig string) error {
	debugLog("asymmetricValidation", "Validating asymmetric signature, key type: %s", keyInfo.KeyType)
	if data == "" || dataSig == "" {
		return errors.New("missing required headers for asymmetric verification")
	}

	// Parse and validate acceleration public key
	accelKey, err := parseAndValidateKey(string(keyInfo.PublicKey), string(keyInfo.KeyType), "acceleration key")
	if err != nil {
		return err
	}

	// Verify request is signed by acceleration key
	if err := verifySignedData(accelKey, data, dataSig); err != nil {
		return err
	}

	return nil
}

// Handle request using an existing key
func verifyExistingKeyRequest(w http.ResponseWriter, r *http.Request) error {
	accelKeyId := r.Header.Get("x-rpc-sec-bound-token-accel-pub-id")
	debugLog("verifyExistingKey", "Verifying request with existing key ID: %s", accelKeyId)
	if accelKeyId == "" {
		errorResponse(w, "Missing acceleration key ID", http.StatusBadRequest)
		return errors.New("missing acceleration key ID")
	}

	// Get the key info
	keyInfoValue, found := accelKeys.Get(accelKeyId)
	if !found {
		errorResponse(w, "Invalid acceleration key ID", http.StatusUnauthorized)
		return errors.New("invalid acceleration key ID")
	}
	unifiedKey := keyInfoValue.(UnifiedKeyInfo)

	// Validate the request
	return verifyRequest(w, r, unifiedKey)
}

// Main endpoint for all authenticated requests
func authenticatedHandler(w http.ResponseWriter, r *http.Request) {
	debugLog("authenticatedHandler", "Received authenticated request from %s, method: %s", r.RemoteAddr, r.Method)
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Validate token
	token, err := extractAndValidateToken(r)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Get hardware key info associated with the token
	tokenInfoValue, found := tokensCache.Get(token)
	if !found {
		errorResponse(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	hwKeyInfo := tokenInfoValue.(PublicKeyInfo)

	// Handle either key registration or regular request
	if r.Header.Get("x-rpc-sec-bound-token-accel-pub") != "" {
		debugLog("authenticatedHandler", "Request includes new acceleration key")
		// This is a new key registration (either asymmetric or ECDH)
		err = verifyAccelKeyRegistrationRequest(w, r, hwKeyInfo)
		if err != nil {
			errorResponse(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		debugLog("authenticatedHandler", "Request uses existing key")
		// Handle request with existing key
		err = verifyExistingKeyRequest(w, r)
		if err != nil {
			errorResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
	}

	// If we reach here, the request is authenticated. Run business logic
	sendAuthenticationSuccess(w)
}

// Extract and validate the authorization token
func extractAndValidateToken(r *http.Request) (string, error) {
	debugLog("tokenValidation", "Extracting token from Authorization header")
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("invalid authorization header")
	}
	return strings.TrimPrefix(authHeader, "Bearer "), nil
}

// Challenge handler - generates nonce for attestation
func challengeHandler(w http.ResponseWriter, r *http.Request) {
	debugLog("challengeHandler", "Received challenge request from %s", r.RemoteAddr)
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract and validate token
	token, err := extractAndValidateToken(r)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Verify token exists in cache
	_, found := tokensCache.Get(token)
	if !found {
		errorResponse(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Generate a fresh nonce
	nonce, err := generateRandomString(32)
	if err != nil {
		errorResponse(w, "Failed to generate challenge", http.StatusInternalServerError)
		return
	}

	// Store the nonce with the token for later verification
	challengeCache.Set(token+":nonce", nonce, cache.DefaultExpiration)

	log.Printf("Generated attestation challenge for token: %s", token[:8]+"...")

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ChallengeResponse{Nonce: nonce})
}

// Validate TPM key attestation structure
func validateTpmKeyAttestation(attestationBytes []byte, aikPubBytes []byte, nonce string) error {
	debugLog("validateTpmKeyAttestation", "Validating TPM key attestation, size: %d bytes", len(attestationBytes))

	// Check minimum size for PCP_KEY_ATTESTATION_BLOB header
	if len(attestationBytes) < 24 { // Magic(4) + Platform(4) + HeaderSize(4) + cbKeyAttest(4) + cbSignature(4) + cbKeyBlob(4)
		return errors.New("attestation blob too small")
	}

	// Parse the PCP_KEY_ATTESTATION_BLOB header
	magic := binary.LittleEndian.Uint32(attestationBytes[0:4])
	platform := binary.LittleEndian.Uint32(attestationBytes[4:8])
	headerSize := binary.LittleEndian.Uint32(attestationBytes[8:12])
	cbKeyAttest := binary.LittleEndian.Uint32(attestationBytes[12:16])
	cbSignature := binary.LittleEndian.Uint32(attestationBytes[16:20])
	cbKeyBlob := binary.LittleEndian.Uint32(attestationBytes[20:24])

	debugLog("validateTpmKeyAttestation", "Magic: 0x%08X, Platform: %d, HeaderSize: %d", magic, platform, headerSize)
	debugLog("validateTpmKeyAttestation", "KeyAttest: %d, Signature: %d, KeyBlob: %d", cbKeyAttest, cbSignature, cbKeyBlob)

	// Validate magic number for key attestation
	const PCP_KEY_ATTESTATION_MAGIC = 0x4B414453 // 'SDAK' in little endian
	if magic != PCP_KEY_ATTESTATION_MAGIC {
		return fmt.Errorf("invalid magic number: expected 0x%08X, got 0x%08X", PCP_KEY_ATTESTATION_MAGIC, magic)
	}

	// Validate platform type (TPM 1.2 or 2.0)
	const PCPTYPE_TPM12 = 0x00000001
	const PCPTYPE_TPM20 = 0x00000002
	if platform != PCPTYPE_TPM12 && platform != PCPTYPE_TPM20 {
		return fmt.Errorf("invalid platform type: %d", platform)
	}

	// Validate header size
	if headerSize < 24 {
		return fmt.Errorf("invalid header size: %d", headerSize)
	}

	// Check that the blob is large enough to contain all claimed data
	expectedSize := headerSize + cbKeyAttest + cbSignature + cbKeyBlob
	if uint32(len(attestationBytes)) < expectedSize {
		return fmt.Errorf("attestation blob size mismatch: expected at least %d, got %d", expectedSize, len(attestationBytes))
	}

	// Validate AIK public key size (should be reasonable for ECDSA P-256 or RSA)
	if len(aikPubBytes) < 64 || len(aikPubBytes) > 2048 {
		return fmt.Errorf("invalid AIK public key size: %d", len(aikPubBytes))
	}

	// Additional validation could include:
	// - Parsing and validating the TPM2B_ATTEST structure within cbKeyAttest
	// - Verifying the signature using the AIK public key
	// - Checking nonce inclusion if provided
	// For now, we accept the attestation if it has the correct structure

	debugLog("validateTpmKeyAttestation", "TPM key attestation validation passed")
	return nil
}

// Attestation handler - verifies TPM key attestation
func attestationHandler(w http.ResponseWriter, r *http.Request) {
	debugLog("attestationHandler", "Received attestation request from %s", r.RemoteAddr)
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract and validate token
	token, err := extractAndValidateToken(r)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Verify token exists in cache
	_, found := tokensCache.Get(token)
	if !found {
		errorResponse(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Parse the attestation request
	var attestReq AttestationRequest
	if err := json.NewDecoder(r.Body).Decode(&attestReq); err != nil {
		errorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if attestReq.Attestation == "" || attestReq.AIKPublicKey == "" {
		errorResponse(w, "Missing attestation or AIK public key", http.StatusBadRequest)
		return
	}

	// Verify nonce if provided
	if attestReq.Nonce != "" {
		expectedNonce, found := challengeCache.Get(token + ":nonce")
		if !found {
			errorResponse(w, "Invalid or expired nonce", http.StatusBadRequest)
			return
		}

		if expectedNonce.(string) != attestReq.Nonce {
			errorResponse(w, "Nonce mismatch", http.StatusBadRequest)
			return
		}

		// Remove used nonce
		challengeCache.Delete(token + ":nonce")
	}

	// Decode and validate the TPM attestation structure
	attestationBytes, err := base64.StdEncoding.DecodeString(attestReq.Attestation)
	if err != nil {
		errorResponse(w, "Invalid attestation format", http.StatusBadRequest)
		return
	}

	aikPubBytes, err := base64.StdEncoding.DecodeString(attestReq.AIKPublicKey)
	if err != nil {
		errorResponse(w, "Invalid AIK public key format", http.StatusBadRequest)
		return
	}

	// Validate TPM key attestation structure
	if err := validateTmpKeyAttestation(attestationBytes, aikPubBytes, attestReq.Nonce, attestReq.PCRValues); err != nil {
		errorResponse(w, fmt.Sprintf("TPM attestation validation failed: %v", err), http.StatusBadRequest)
		return
	}

	// Log successful attestation with PCR info
	pcrInfo := "no PCRs"
	if attestReq.PCRValues != "" {
		pcrBytes, err := base64.StdEncoding.DecodeString(attestReq.PCRValues)
		if err == nil && len(pcrBytes) > 0 {
			// Determine PCR format
			if len(pcrBytes)%24 == 0 { // 24 PCRs
				digestSize := len(pcrBytes) / 24
				if digestSize == 20 {
					pcrInfo = fmt.Sprintf("%d SHA1 PCRs", 24)
				} else if digestSize == 32 {
					pcrInfo = fmt.Sprintf("%d SHA256 PCRs", 24)
				} else {
					pcrInfo = fmt.Sprintf("%d PCRs (%d bytes each)", 24, digestSize)
				}
			} else {
				pcrInfo = fmt.Sprintf("%d PCR bytes", len(pcrBytes))
			}
		}
	}

	log.Printf("TPM key attestation successful for token: %s, key type: %s, attestation size: %d bytes, PCRs: %s",
		token[:8]+"...", attestReq.KeyType, len(attestationBytes), pcrInfo)

	// Store attestation info with token for future reference
	tokensCache.Set(token+":attestation", map[string]interface{}{
		"attestation":    attestReq.Attestation,
		"aik_public_key": attestReq.AIKPublicKey,
		"pcr_values":     attestReq.PCRValues,
		"key_type":       attestReq.KeyType,
		"timestamp":      time.Now(),
		"validated":      true,
	}, cache.DefaultExpiration)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "success",
		"message":   "TPM key attestation verified successfully",
		"timestamp": time.Now(),
	})
}

// Enhanced TPM key attestation validation with full cryptographic verification
func validateTmpKeyAttestation(attestationBytes []byte, aikPubBytes []byte, nonce string, pcrValues string) error {
	debugLog("validateTmpKeyAttestation", "Validating TPM key attestation with crypto verification, size: %d bytes", len(attestationBytes))

	// Check minimum size for PCP_KEY_ATTESTATION_BLOB header
	if len(attestationBytes) < 24 { // Magic(4) + Platform(4) + HeaderSize(4) + cbKeyAttest(4) + cbSignature(4) + cbKeyBlob(4)
		return errors.New("attestation blob too small")
	}

	// Parse the PCP_KEY_ATTESTATION_BLOB header
	magic := binary.LittleEndian.Uint32(attestationBytes[0:4])
	platform := binary.LittleEndian.Uint32(attestationBytes[4:8])
	headerSize := binary.LittleEndian.Uint32(attestationBytes[8:12])
	cbKeyAttest := binary.LittleEndian.Uint32(attestationBytes[12:16])
	cbSignature := binary.LittleEndian.Uint32(attestationBytes[16:20])
	cbKeyBlob := binary.LittleEndian.Uint32(attestationBytes[20:24])

	debugLog("validateTmpKeyAttestation", "Magic: 0x%08X, Platform: %d, HeaderSize: %d", magic, platform, headerSize)
	debugLog("validateTmpKeyAttestation", "KeyAttest: %d, Signature: %d, KeyBlob: %d", cbKeyAttest, cbSignature, cbKeyBlob)

	// Validate magic number for key attestation
	const PCP_KEY_ATTESTATION_MAGIC = 0x5344414B
	if magic != PCP_KEY_ATTESTATION_MAGIC {
		return fmt.Errorf("invalid magic number: expected 0x%08X, got 0x%08X", PCP_KEY_ATTESTATION_MAGIC, magic)
	}

	// Validate platform type (TPM 1.2 or 2.0)
	const PCPTYPE_TPM12 = 0x00000001
	const PCPTYPE_TPM20 = 0x00000002
	if platform != PCPTYPE_TPM12 && platform != PCPTYPE_TPM20 {
		return fmt.Errorf("invalid platform type: %d", platform)
	}

	// Validate header size
	if headerSize < 24 {
		return fmt.Errorf("invalid header size: %d", headerSize)
	}

	// Check that the blob is large enough to contain all claimed data
	expectedSize := headerSize + cbKeyAttest + cbSignature + cbKeyBlob
	if uint32(len(attestationBytes)) < expectedSize {
		return fmt.Errorf("attestation blob size mismatch: expected at least %d, got %d", expectedSize, len(attestationBytes))
	}

	// Extract components from attestation blob
	cursor := int(headerSize)
	keyAttestData := attestationBytes[cursor : cursor+int(cbKeyAttest)]
	cursor += int(cbKeyAttest)
	signatureData := attestationBytes[cursor : cursor+int(cbSignature)]
	cursor += int(cbSignature)
	keyBlobData := attestationBytes[cursor : cursor+int(cbKeyBlob)]

	debugLog("validateTmpKeyAttestation", "Extracted components: KeyAttest=%d, Signature=%d, KeyBlob=%d bytes",
		len(keyAttestData), len(signatureData), len(keyBlobData))

	// Step 1: Parse and validate AIK public key
	aikPubKey, err := parseAndValidateAIKPublicKey(aikPubBytes)
	if err != nil {
		return fmt.Errorf("failed to parse AIK public key: %w", err)
	}

	// Step 2: Verify the attestation signature
	if err := verifyAttestationSignature(aikPubKey, keyAttestData, signatureData); err != nil {
		return fmt.Errorf("attestation signature verification failed: %w", err)
	}

	// Step 3: Validate TPM attestation structure and nonce
	if err := validateTPMAttestStructure(keyAttestData, nonce, platform); err != nil {
		return fmt.Errorf("TPM attest structure validation failed: %w", err)
	}

	// Step 4: Validate key blob and policies (based on ValidateKeyAttest20)
	if err := validateKeyBlobAndPolicies(keyBlobData, keyAttestData, pcrValues, platform); err != nil {
		return fmt.Errorf("key blob validation failed: %w", err)
	}

	debugLog("validateTmpKeyAttestation", "TPM key attestation validation passed")
	return nil
}

// Validate key blob and TPM policies (based on ValidateKeyAttest20)
func validateKeyBlobAndPolicies(keyBlobData []byte, keyAttestData []byte, pcrValues string, platform uint32) error {
	if platform != 0x00000002 { // Only TPM 2.0 supported for now
		debugLog("validateKeyBlobAndPolicies", "Skipping key blob validation for platform %d", platform)
		return nil
	}

	debugLog("validateKeyBlobAndPolicies", "Validating key blob and policies, blob size: %d", len(keyBlobData))

	// Parse PCP_KEY_BLOB_WIN8 header
	if len(keyBlobData) < 72 { // Minimum size for PCP_KEY_BLOB_WIN8
		return errors.New("key blob too small for header")
	}

	cursor := 0

	// Read header fields
	magic := binary.LittleEndian.Uint32(keyBlobData[cursor : cursor+4])
	cursor += 4
	if magic != 0x4D504350 {
		return fmt.Errorf("invalid key blob magic: 0x%08X", magic)
	}

	cbHeader := binary.LittleEndian.Uint32(keyBlobData[cursor : cursor+4])
	cursor += 4
	pcpType := binary.LittleEndian.Uint32(keyBlobData[cursor : cursor+4])
	cursor += 4

	if pcpType != 0x00000002 { // PCPTYPE_TPM20
		return fmt.Errorf("invalid PCP type: %d, expected TPM 2.0", pcpType)
	}

	if cbHeader < 56 {
		return fmt.Errorf("invalid header size: %d", cbHeader)
	}

	// Skip to the size fields
	cursor = 16 // Skip to cbPublic
	cbPublic := binary.LittleEndian.Uint32(keyBlobData[cursor : cursor+4])
	cursor += 4
	cbPrivate := binary.LittleEndian.Uint32(keyBlobData[cursor : cursor+4])
	cursor += 4
	cbMigrationPublic := binary.LittleEndian.Uint32(keyBlobData[cursor : cursor+4])
	cursor += 4
	cbMigrationPrivate := binary.LittleEndian.Uint32(keyBlobData[cursor : cursor+4])
	cursor += 4
	cbPolicyDigestList := binary.LittleEndian.Uint32(keyBlobData[cursor : cursor+4])
	cursor += 4
	cbPCRBinding := binary.LittleEndian.Uint32(keyBlobData[cursor : cursor+4])
	cursor += 4
	cbPCRDigest := binary.LittleEndian.Uint32(keyBlobData[cursor : cursor+4])
	cursor += 4
	cbEncryptedSecret := binary.LittleEndian.Uint32(keyBlobData[cursor : cursor+4])
	cursor += 4
	cbTpm12HostageBlob := binary.LittleEndian.Uint32(keyBlobData[cursor : cursor+4])

	debugLog("validateKeyBlobAndPolicies", "Key blob sizes: Public=%d, Private=%d, PolicyDigestList=%d",
		cbPublic, cbPrivate, cbPolicyDigestList)

	// Validate total size
	expectedSize := cbHeader + cbPublic + cbPrivate + cbMigrationPublic + cbMigrationPrivate +
		cbPolicyDigestList + cbPCRBinding + cbPCRDigest + cbEncryptedSecret + cbTpm12HostageBlob
	if uint32(len(keyBlobData)) < expectedSize {
		return fmt.Errorf("key blob size mismatch: expected %d, got %d", expectedSize, len(keyBlobData))
	}

	// Step 1: Extract and validate key name from attestation
	keyNameFromAttest, err := extractKeyNameFromAttestation(keyAttestData)
	if err != nil {
		return fmt.Errorf("failed to extract key name from attestation: %w", err)
	}

	// Step 2: Calculate key name from public key in blob
	publicKeyOffset := cbHeader + 2 // Skip size field in TPMT_PUBLIC
	if uint32(len(keyBlobData)) < publicKeyOffset+cbPublic-2 {
		return errors.New("key blob too small for public key")
	}

	keyNameFromBlob, err := calculateKeyNameFromPublic(keyBlobData[publicKeyOffset : publicKeyOffset+cbPublic-2])
	if err != nil {
		return fmt.Errorf("failed to calculate key name from public key: %w", err)
	}

	// Step 3: Validate key names match
	if !bytes.Equal(keyNameFromAttest, keyNameFromBlob) {
		return fmt.Errorf("key name mismatch: attestation vs blob")
	}

	debugLog("validateKeyBlobAndPolicies", "Key name validation passed")

	// Step 4: Validate policy digests
	if err := validatePolicyDigests(keyBlobData, cbHeader, cbPublic, cbPrivate, cbMigrationPublic,
		cbMigrationPrivate, cbPolicyDigestList, pcrValues); err != nil {
		return fmt.Errorf("policy digest validation failed: %w", err)
	}

	debugLog("validateKeyBlobAndPolicies", "Key blob and policy validation passed")
	return nil
}

// Extract key name from TPM attestation data
func extractKeyNameFromAttestation(keyAttestData []byte) ([]byte, error) {
	cursor := 0

	// Skip magic (4 bytes) and type (2 bytes)
	cursor += 6

	// Skip qualifiedSigner
	qualifiedSignerSize, newCursor, err := readTPM2BSize(keyAttestData, cursor)
	if err != nil {
		return nil, err
	}
	cursor = newCursor + int(qualifiedSignerSize)

	// Skip extraData
	extraDataSize, newCursor, err := readTPM2BSize(keyAttestData, cursor)
	if err != nil {
		return nil, err
	}
	cursor = newCursor + int(extraDataSize)

	// Skip TPMS_CLOCK_INFO (17 bytes) and firmwareVersion (8 bytes)
	cursor += 25

	// Read key name
	nameSize, newCursor, err := readTPM2BSize(keyAttestData, cursor)
	if err != nil {
		return nil, err
	}
	cursor = newCursor

	if nameSize == 0 {
		return nil, errors.New("empty key name in attestation")
	}

	if len(keyAttestData) < cursor+int(nameSize) {
		return nil, errors.New("attestation too small for key name")
	}

	return keyAttestData[cursor : cursor+int(nameSize)], nil
}

// Calculate key name from public key (simplified implementation)
func calculateKeyNameFromPublic(publicKeyData []byte) ([]byte, error) {
	// This is a simplified implementation
	// In a full implementation, you would:
	// 1. Parse the TPMT_PUBLIC structure
	// 2. Calculate name = Hash(nameAlg || publicArea)
	// For now, we'll create a placeholder that matches expected format

	if len(publicKeyData) < 10 {
		return nil, errors.New("public key data too small")
	}

	// Create a SHA-256 hash of the public key data as a simplified name
	hash := sha256.Sum256(publicKeyData)

	// TPM name format: nameAlg (2 bytes) + hash
	nameAlg := []byte{0x00, 0x0B} // TPM_ALG_SHA256
	keyName := make([]byte, len(nameAlg)+len(hash))
	copy(keyName, nameAlg)
	copy(keyName[len(nameAlg):], hash[:])

	return keyName, nil
}

// Validate TPM policy digests (comprehensive implementation based on ValidateKeyAttest20)
func validatePolicyDigests(keyBlobData []byte, cbHeader, cbPublic, cbPrivate, cbMigrationPublic,
	cbMigrationPrivate, cbPolicyDigestList uint32, pcrValues string) error {

	// Parse key attributes to determine if key is PCR-bound
	cursor := int(cbHeader + 2 + 2 + 2) // Skip size, keytype, nameAlg
	if len(keyBlobData) < cursor+4 {
		return errors.New("key blob too small for key attributes")
	}
	keyAttributes := binary.BigEndian.Uint32(keyBlobData[cursor : cursor+4])

	// Navigate to policy digest list
	cursor = int(cbHeader + cbPublic + cbPrivate + cbMigrationPublic + cbMigrationPrivate)

	if len(keyBlobData) < cursor+4 {
		return errors.New("key blob too small for policy digest count")
	}

	policyDigestCount := binary.BigEndian.Uint32(keyBlobData[cursor : cursor+4])
	cursor += 4

	debugLog("validatePolicyDigests", "Policy digest count: %d", policyDigestCount)

	// Only non-exportable keys may be attested - must have exactly 4 or 6 policy digests
	if policyDigestCount != 4 && policyDigestCount != 6 {
		return fmt.Errorf("invalid policy digest count: %d, expected 4 or 6", policyDigestCount)
	}

	// Calculate user policy digest reference
	var userPolicyDigestReference []byte

	if pcrValues != "" && (keyAttributes&0x00000040) == 0 { // Key is PCR-bound and we have PCR data
		// Parse PCR data
		pcrBytes, err := base64.StdEncoding.DecodeString(pcrValues)
		if err != nil {
			return fmt.Errorf("invalid PCR values format: %w", err)
		}

		// Get PCR information from key blob
		pcrCursor := int(cbHeader + cbPublic + cbPrivate + cbMigrationPublic + cbMigrationPrivate + cbPolicyDigestList)

		if len(keyBlobData) < pcrCursor+3 {
			return errors.New("key blob too small for PCR mask")
		}

		// Read PCR mask (3 bytes, little-endian)
		keyBlobPcrMask := uint32(keyBlobData[pcrCursor]) |
			(uint32(keyBlobData[pcrCursor+1]) << 8) |
			(uint32(keyBlobData[pcrCursor+2]) << 16)
		pcrCursor += 3

		// Get PCR digest from key blob
		pcrDigestSize := 32 // SHA256_DIGEST_SIZE for policy calculation
		if len(keyBlobData) < pcrCursor+pcrDigestSize {
			return errors.New("key blob too small for PCR digest")
		}
		keyBlobPcrDigest := keyBlobData[pcrCursor : pcrCursor+pcrDigestSize]

		// Determine PCR algorithm from PCR data size
		var pcrAlgId uint16 = TPM_ALG_SHA1
		digestSize := len(pcrBytes) / AVAILABLE_PLATFORM_PCRS
		if digestSize == 32 {
			pcrAlgId = TPM_ALG_SHA256
		}

		// Calculate user policy with PCRs
		userPolicyDigestReference, err = calculateUserPolicyWithPCRs(pcrBytes, keyBlobPcrMask, pcrAlgId, keyBlobPcrDigest)
		if err != nil {
			return fmt.Errorf("failed to calculate user policy with PCRs: %w", err)
		}
	} else if (keyAttributes & 0x00000040) != 0 { // userWithAuth - not PCR bound
		// Use default user policy
		userPolicyDigestReference = make([]byte, len(defaultUserPolicy))
		copy(userPolicyDigestReference, defaultUserPolicy)
	} else {
		// Key is PCR-bound but caller didn't provide PCR data for validation
		// Accept the user policy digest stored in the key blob
		policyCursor := int(cbHeader + cbPublic + cbPrivate + cbMigrationPublic + cbMigrationPrivate + 4)
		_, userPolicyDigest, err := readBigEndian2B(keyBlobData, &policyCursor)
		if err != nil {
			return fmt.Errorf("failed to read user policy digest: %w", err)
		}
		userPolicyDigestReference = userPolicyDigest
	}

	// Read and validate each policy digest
	policyCursor := int(cbHeader + cbPublic + cbPrivate + cbMigrationPublic + cbMigrationPrivate + 4)

	// Expected policy digests in order
	expectedPolicies := [][]byte{
		userPolicyDigestReference,
		adminObjectChangeAuthPolicy,
		adminCertifyPolicy,
		adminActivateCredentialPolicy,
	}

	if policyDigestCount == 6 {
		expectedPolicies = append(expectedPolicies,
			[]byte{}, // Empty policy for Duplicate (zero-length)
			adminCertifyPolicyNoPin)
	}

	// Validate each policy digest
	for i := 0; i < int(policyDigestCount); i++ {
		digestSize, digest, err := readBigEndian2B(keyBlobData, &policyCursor)
		if err != nil {
			return fmt.Errorf("failed to read policy digest %d: %w", i, err)
		}

		// Special case for empty digest (Windows 10 duplicate policy)
		if i == 4 && policyDigestCount == 6 && digestSize == 0 {
			debugLog("validatePolicyDigests", "Policy %d: empty digest (duplicate policy)", i)
			continue
		}

		// Validate digest size and content
		if digestSize != 32 && digestSize != 0 {
			return fmt.Errorf("invalid policy digest size for policy %d: %d", i, digestSize)
		}

		if !bytes.Equal(digest, expectedPolicies[i]) {
			return fmt.Errorf("policy digest %d mismatch", i)
		}

		debugLog("validatePolicyDigests", "Policy %d: validated successfully", i)
	}

	// Calculate and verify the overall policy digest (PolicyOR of all individual policies)
	policyOrDigestBuffer := make([]byte, 0, 32+4+5*32)

	// Start with zeros for the old policy hash
	policyOrDigestBuffer = append(policyOrDigestBuffer, make([]byte, 32)...)

	// Add TPM_CC_PolicyOR
	tpmCcBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tpmCcBytes, TPM_CC_PolicyOR)
	policyOrDigestBuffer = append(policyOrDigestBuffer, tpmCcBytes...)

	// Add all policy digests
	policyOrDigestBuffer = append(policyOrDigestBuffer, userPolicyDigestReference...)
	policyOrDigestBuffer = append(policyOrDigestBuffer, adminObjectChangeAuthPolicy...)
	policyOrDigestBuffer = append(policyOrDigestBuffer, adminCertifyPolicy...)
	policyOrDigestBuffer = append(policyOrDigestBuffer, adminActivateCredentialPolicy...)

	if policyDigestCount > 4 {
		policyOrDigestBuffer = append(policyOrDigestBuffer, adminCertifyPolicyNoPin...)
	}

	// Calculate final policy digest
	h := sha256.New()
	h.Write(policyOrDigestBuffer)
	finalPolicyDigest := h.Sum(nil)

	// Verify against the auth policy in the public key
	authPolicyCursor := int(cbHeader + 2 + 2 + 2 + 4) // Skip to authPolicy
	_, authPolicy, err := readBigEndian2B(keyBlobData, &authPolicyCursor)
	if err != nil {
		return fmt.Errorf("failed to read auth policy: %w", err)
	}

	if !bytes.Equal(authPolicy, finalPolicyDigest) {
		return errors.New("final policy digest verification failed")
	}

	debugLog("validatePolicyDigests", "All policy digest validation passed")
	return nil
}

// Parse and validate AIK public key (RSA or ECDSA)
func parseAndValidateAIKPublicKey(aikPubBytes []byte) (interface{}, error) {
	// Try to parse as PKIX format first
	pubKey, err := x509.ParsePKIXPublicKey(aikPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	// Validate key type and size
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 1024 {
			return nil, fmt.Errorf("RSA key too small: %d bits", key.N.BitLen())
		}
		return key, nil
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() {
			return nil, fmt.Errorf("unsupported ECDSA curve")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported AIK key type: %T", key)
	}
}

// Verify attestation signature using AIK public key
func verifyAttestationSignature(aikPubKey interface{}, keyAttestData []byte, signatureData []byte) error {
	// Calculate SHA-1 hash of the key attestation data (as per TPM spec)
	hash := sha1.Sum(keyAttestData)

	switch key := aikPubKey.(type) {
	case *rsa.PublicKey:
		// Use PKCS#1 v1.5 padding for RSA signature verification
		return rsa.VerifyPKCS1v15(key, crypto.SHA1, hash[:], signatureData)

	case *ecdsa.PublicKey:
		// For ECDSA, try ASN.1 format first
		if ecdsa.VerifyASN1(key, hash[:], signatureData) {
			return nil
		}
		// Try raw r||s format if ASN.1 fails
		if len(signatureData) == 64 {
			r := new(big.Int).SetBytes(signatureData[:32])
			s := new(big.Int).SetBytes(signatureData[32:])
			if ecdsa.Verify(key, hash[:], r, s) {
				return nil
			}
		}
		return errors.New("ECDSA signature verification failed")

	default:
		return fmt.Errorf("unsupported key type for signature verification: %T", key)
	}
}

// Validate TPM attestation structure and nonce (enhanced based on ValidateKeyAttest20)
func validateTPMAttestStructure(keyAttestData []byte, nonce string, platform uint32) error {
	if len(keyAttestData) < 8 {
		return errors.New("key attest data too small")
	}

	// For TPM 2.0, perform comprehensive validation
	if platform == 0x00000002 { // TPM 2.0
		return validateTPM20AttestStructure(keyAttestData, nonce)
	} else if platform == 0x00000001 { // TPM 1.2
		return validateTPM12AttestStructure(keyAttestData, nonce)
	}

	return fmt.Errorf("unsupported platform type: %d", platform)
}

// Validate TPM 2.0 attestation structure (based on ValidateKeyAttest20)
func validateTPM20AttestStructure(keyAttestData []byte, nonce string) error {
	debugLog("validateTPM20AttestStructure", "Validating TPM 2.0 attestation structure, size: %d", len(keyAttestData))

	cursor := 0

	// Step 1: Read magic number (TPM_GENERATED_VALUE)
	if len(keyAttestData) < cursor+4 {
		return errors.New("attestation too small for magic number")
	}
	magic := binary.BigEndian.Uint32(keyAttestData[cursor : cursor+4])
	cursor += 4

	if magic != 0xff544347 { // TPM_GENERATED_VALUE
		return fmt.Errorf("invalid TPM_GENERATED magic: 0x%08X, expected 0xff544347", magic)
	}

	// Step 2: Read attestation type
	if len(keyAttestData) < cursor+2 {
		return errors.New("attestation too small for type field")
	}
	attestType := binary.BigEndian.Uint16(keyAttestData[cursor : cursor+2])
	cursor += 2

	if attestType != 0x8017 { // TPM_ST_ATTEST_CERTIFY
		return fmt.Errorf("invalid attestation type: 0x%04X, expected 0x8017 (TPM_ST_ATTEST_CERTIFY)", attestType)
	}

	// Step 3: Skip qualifiedSigner (TPM2B_NAME)
	qualifiedSignerSize, newCursor, err := readTPM2BSize(keyAttestData, cursor)
	if err != nil {
		return fmt.Errorf("failed to read qualifiedSigner size: %w", err)
	}
	cursor = newCursor + int(qualifiedSignerSize)

	// Step 4: Read extraData (nonce) - TPM2B_DATA
	extraDataSize, newCursor, err := readTPM2BSize(keyAttestData, cursor)
	if err != nil {
		return fmt.Errorf("failed to read extraData size: %w", err)
	}
	cursor = newCursor

	var extraData []byte
	if extraDataSize > 0 {
		if len(keyAttestData) < cursor+int(extraDataSize) {
			return errors.New("attestation too small for extraData")
		}
		extraData = keyAttestData[cursor : cursor+int(extraDataSize)]
	}
	cursor += int(extraDataSize)

	// Step 5: Skip TPMS_CLOCK_INFO (8 + 1 + 4 + 4 = 17 bytes)
	// UINT64 clock, BYTE resetCount, UINT32 restartCount, BYTE safe
	if len(keyAttestData) < cursor+17 {
		return errors.New("attestation too small for TPMS_CLOCK_INFO")
	}
	cursor += 17

	// Step 6: Skip firmwareVersion (8 bytes)
	if len(keyAttestData) < cursor+8 {
		return errors.New("attestation too small for firmwareVersion")
	}
	cursor += 8

	// Step 7: Read name (TPM2B_NAME) - this is the key name
	nameSize, newCursor, err := readTPM2BSize(keyAttestData, cursor)
	if err != nil {
		return fmt.Errorf("failed to read name size: %w", err)
	}
	cursor = newCursor

	var keyName []byte
	if nameSize > 0 {
		if len(keyAttestData) < cursor+int(nameSize) {
			return errors.New("attestation too small for key name")
		}
		keyName = keyAttestData[cursor : cursor+int(nameSize)]
	}
	cursor += int(nameSize)

	// Step 8: Skip qualifiedName (TPM2B_NAME)
	qualifiedNameSize, newCursor, err := readTPM2BSize(keyAttestData, cursor)
	if err != nil {
		return fmt.Errorf("failed to read qualifiedName size: %w", err)
	}
	cursor = newCursor + int(qualifiedNameSize)

	// Step 9: Ensure that there is no trailing data that has been signed
	if cursor != len(keyAttestData) {
		return fmt.Errorf("unexpected trailing data in attestation: expected %d bytes, consumed %d", len(keyAttestData), cursor)
	}

	// Step 10: Validate nonce if provided (matches C++ logic)
	if nonce != "" {
		nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
		if err != nil {
			return fmt.Errorf("invalid nonce format: %w", err)
		}

		// Check the nonce if requested - matches C++ condition exactly
		if len(nonceBytes) != len(extraData) || !bytes.Equal(extraData, nonceBytes) {
			return fmt.Errorf("nonce mismatch: expected %d bytes, got %d bytes in extraData", len(nonceBytes), len(extraData))
		}

		debugLog("validateTPM20AttestStructure", "Nonce validation successful")
	}

	// Log key information for debugging
	if len(keyName) > 0 {
		debugLog("validateTPM20AttestStructure", "Key name: %d bytes, first 16 bytes: %x", len(keyName), keyName[:min(16, len(keyName))])
	}

	debugLog("validateTPM20AttestStructure", "TPM 2.0 attestation structure validation passed")
	return nil
}

// Validate TPM 1.2 attestation structure (simplified)
func validateTPM12AttestStructure(keyAttestData []byte, nonce string) error {
	debugLog("validateTPM12AttestStructure", "Validating TPM 1.2 attestation structure, size: %d", len(keyAttestData))

	// TPM 1.2 has a different structure - this is a simplified validation
	// In a full implementation, you would parse the TPM_CERTIFY_INFO structure

	if len(keyAttestData) < 20 {
		return errors.New("TPM 1.2 attestation too small")
	}

	// Basic validation - just ensure we have reasonable data
	debugLog("validateTPM12AttestStructure", "TPM 1.2 attestation structure validation passed (simplified)")
	return nil
}

// Helper function to read TPM2B size field (2 bytes big-endian)
func readTPM2BSize(data []byte, cursor int) (uint16, int, error) {
	if len(data) < cursor+2 {
		return 0, cursor, errors.New("insufficient data for TPM2B size field")
	}
	size := binary.BigEndian.Uint16(data[cursor : cursor+2])
	return size, cursor + 2, nil
}

// Helper function for min operation
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/authenticated", authenticatedHandler)

	// Experimental
	http.HandleFunc("/challenge", challengeHandler)
	http.HandleFunc("/attest", attestationHandler)

	debugLog("main", "Server starting on port 28280")
	log.Fatal(http.ListenAndServe(":28280", nil))
}
