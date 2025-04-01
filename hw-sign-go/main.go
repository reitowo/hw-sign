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
	KeyTypeECDSA   KeyType = "ecdsa"
	KeyTypeRSAPSS  KeyType = "rsa-pss"
	KeyTypeECDH    KeyType = "ecdh"
)

// Unified key structures for better organization
type PublicKeyInfo struct {
	Key  []byte
	Type KeyType
}

type UnifiedKeyInfo struct {
	PublicKey     []byte      // Public key for asymmetric crypto
	KeyType       KeyType     // Type of key (ecdsa, rsa-pss, ed25519)
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
	usersCache  = cache.New(defaultCacheExpiry, cleanupInterval) // Cache for user data
	accelKeys   = cache.New(defaultCacheExpiry, cleanupInterval) // Cache for unified acceleration keys
	tokensCache = cache.New(defaultCacheExpiry, cleanupInterval) // Cache for tokens and associated hardware keys
)

// ============ Crypto Utility Functions ============

// Generate cryptographically secure random string
func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// Parse public key from base64 encoded string based on key type
func parsePublicKey(keyData string, keyType string) (interface{}, error) {
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
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-rpc-sec-dbcs-hw-pub, x-rpc-sec-dbcs-hw-pub-type, x-rpc-sec-dbcs-accel-pub, x-rpc-sec-dbcs-accel-pub-type, x-rpc-sec-dbcs-accel-pub-sig, x-rpc-sec-dbcs-data, x-rpc-sec-dbcs-data-sig, x-rpc-sec-dbcs-accel-pub-id")
	w.Header().Set("Access-Control-Expose-Headers", "x-rpc-sec-dbcs-accel-pub-id, x-rpc-sec-dbcs-accel-pub")
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
	hwPubKey := r.Header.Get("x-rpc-sec-dbcs-hw-pub")
	hwPubType := r.Header.Get("x-rpc-sec-dbcs-hw-pub-type")

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

// Handle acceleration key registration (both asymmetric and ECDH)
func verifyAccelKeyRegistrationRequest(w http.ResponseWriter, r *http.Request, hwKeyInfo PublicKeyInfo) error {
	// Verify acceleration key registration
	accelPub := r.Header.Get("x-rpc-sec-dbcs-accel-pub")
	accelPubType := r.Header.Get("x-rpc-sec-dbcs-accel-pub-type")
	accelPubSig := r.Header.Get("x-rpc-sec-dbcs-accel-pub-sig")

	// Parse hardware key for verification
	hwKey, err := parseAndValidateKey(string(hwKeyInfo.Key), string(hwKeyInfo.Type), "hardware key")
	if err != nil {
		errorResponse(w, err.Error(), http.StatusUnauthorized)
		return err
	}

	// Verify acceleration key is signed by hardware key
	if err := verifySignedData(hwKey, accelPub, accelPubSig); err != nil {
		errorResponse(w, err.Error(), http.StatusUnauthorized)
		return err
	}

	// Generate key ID
	accelKeyId, err := generateRandomString(16)
	if err != nil {
		errorResponse(w, "Failed to generate key ID", http.StatusInternalServerError)
		return err
	}

	// Determine if this is an ECDH key exchange
	isECDH := strings.ToLower(accelPubType) == string(KeyTypeECDH)

	// Create the unified key info
	unifiedKey := UnifiedKeyInfo{
		PublicKey: []byte(accelPub),
		KeyType:   KeyType(strings.ToLower(accelPubType)),
	}

	// Handle ECDH specific key exchange
	if isECDH {
		if err := setupECDHExchange(w, accelPub, &unifiedKey); err != nil {
			errorResponse(w, err.Error(), http.StatusBadRequest)
			return err
		}
	}

	// Store the unified key with its ID
	accelKeys.Set(accelKeyId, unifiedKey, cache.DefaultExpiration)
	w.Header().Set("x-rpc-sec-dbcs-accel-pub-id", accelKeyId)

	// Process this initial request with hardware key context if it's ECDH
	if isECDH {
		// Add hardware key to the unified key for ECDH initial validation
		unifiedKey.HwKey = hwKey
	}

	// For both ECDH and regular asymmetric keys, handle the request
	return verifyRequest(w, r, unifiedKey)
}

// Setup ECDH key exchange
func setupECDHExchange(w http.ResponseWriter, accelPub string, unifiedKey *UnifiedKeyInfo) error {
	// Parse client's ECDH public key
	clientECDHPub, err := parsePublicKey(accelPub, string(KeyTypeECDH))
	if err != nil {
		return fmt.Errorf("invalid ECDH public key: %v", err)
	}

	// Generate server's ECDH key pair
	serverECDHPriv, err := generateECDHKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate server ECDH key: %v", err)
	}

	// Export server's public key for the client
	serverPubKeyBytes := serverECDHPriv.PublicKey().Bytes()
	serverPubKeyBase64 := base64.StdEncoding.EncodeToString(serverPubKeyBytes)
	w.Header().Set("x-rpc-sec-dbcs-accel-pub", serverPubKeyBase64)

	// Compute the shared secret
	clientPubKey, ok := clientECDHPub.(*ecdh.PublicKey)
	if !ok {
		return errors.New("invalid ECDH public key type")
	}

	sharedSecret, err := computeSharedSecret(serverECDHPriv, clientPubKey)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %v", err)
	}

	// Save the symmetric key in the unified key info
	unifiedKey.SymmetricKey = sharedSecret
	unifiedKey.ServerPrivKey = serverECDHPriv

	return nil
}

// Verify authenticated requests
func verifyRequest(w http.ResponseWriter, r *http.Request, keyInfo UnifiedKeyInfo) error {
	// Get data and signature from request
	data := r.Header.Get("x-rpc-sec-dbcs-data")
	dataSig := r.Header.Get("x-rpc-sec-dbcs-data-sig")

	// Log the full request headers for debugging
	log.Printf("Request debug - headers: %+v", r.Header)

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
		// Handle HMAC case
		if err := validateHMACRequest(keyInfo.SymmetricKey, data, dataSig); err != nil {
			log.Printf("HMAC validation failed: %v", err)
			errorResponse(w, err.Error(), http.StatusUnauthorized)
			return err
		}
		log.Printf("HMAC auth successful: %s", data)
	} else {
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
	// Check for key ID
	accelKeyId := r.Header.Get("x-rpc-sec-dbcs-accel-pub-id")
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
	if r.Header.Get("x-rpc-sec-dbcs-accel-pub") != "" {
		// This is a new key registration (either asymmetric or ECDH)
		err = verifyAccelKeyRegistrationRequest(w, r, hwKeyInfo)
		if err != nil {
			errorResponse(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
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
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("invalid authorization header")
	}
	return strings.TrimPrefix(authHeader, "Bearer "), nil
}

func main() {
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/authenticated", authenticatedHandler)

	log.Println("Starting server on :28280")
	log.Fatal(http.ListenAndServe(":28280", nil))
}
