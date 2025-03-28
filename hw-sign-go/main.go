package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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

type KeyType string

const (
	KeyTypeEd25519 KeyType = "ed25519"
	KeyTypeECDSA   KeyType = "ecdsa"
	KeyTypeRSAPSS  KeyType = "rsa-pss"
)

type PublicKeyInfo struct {
	Key  []byte
	Type KeyType
}

var (
	usersCache  = cache.New(3*time.Hour, 10*time.Minute) // Cache for user data
	accelKeys   = cache.New(3*time.Hour, 10*time.Minute) // Cache for accelerated keys
	tokensCache = cache.New(3*time.Hour, 10*time.Minute) // Cache for tokens and associated hardware keys
)

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func parsePublicKey(keyData string, keyType string) (interface{}, error) {
	decoded, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	// Normalize key type to lowercase
	keyType = strings.ToLower(keyType)

	switch keyType {
	case string(KeyTypeEd25519):
		if len(decoded) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 key size")
		}
		return ed25519.PublicKey(decoded), nil

	case string(KeyTypeECDSA):
		if len(decoded) == 65 && decoded[0] == 0x04 {
			return parseRawECDSAPublicKeyX962(decoded)
		}

		// Both ECDSA and RSA keys are expected to be in ASN.1 PKIX format
		key, err := x509.ParsePKIXPublicKey(decoded)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}

		if ecKey, ok := key.(*ecdsa.PublicKey); ok {
			return ecKey, nil
		}
		return nil, errors.New("key is not ECDSA")

	case string(KeyTypeRSAPSS):
		key, err := x509.ParsePKIXPublicKey(decoded)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		if rsaKey, ok := key.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
		return nil, errors.New("key is not RSA")
	}

	return nil, errors.New("unsupported key type")
}

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

// Add CORS headers helper function
func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-rpc-sec-dbcs-hw-pub, x-rpc-sec-dbcs-hw-pub-type, x-rpc-sec-dbcs-accel-pub, x-rpc-sec-dbcs-accel-pub-type, x-rpc-sec-dbcs-accel-pub-sig, x-rpc-sec-dbcs-data, x-rpc-sec-dbcs-data-sig, x-rpc-sec-dbcs-accel-pub-id")
	w.Header().Set("Access-Control-Expose-Headers", "x-rpc-sec-dbcs-accel-pub-id")
}

// Helper function for error response with CORS headers
func errorResponse(w http.ResponseWriter, message string, status int) {
	setCORSHeaders(w)
	http.Error(w, message, status)
}

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

	// Store user data only
	usersCache.Set(userData.Username, userData, cache.DefaultExpiration)

	log.Printf("Registered user: %s", userData.Username)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

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

	// Get and validate hardware public key and type
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

	// Generate token
	token, err := generateRandomString(32)
	if err != nil {
		errorResponse(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Store token with hardware key info
	tokensCache.Set(token, PublicKeyInfo{
		Key:  []byte(hwPubKey),
		Type: KeyType(strings.ToLower(hwPubType)),
	}, cache.DefaultExpiration)

	log.Printf("User logged in: %s with key type: %s", credentials.Username, hwPubType)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// Helper function to verify signatures with proper error handling
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

// Helper function for key parsing and validation
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

func handleAccelKeyRegistration(w http.ResponseWriter, r *http.Request, hwKeyInfo PublicKeyInfo) {
	// Verify acceleration key registration
	accelPub := r.Header.Get("x-rpc-sec-dbcs-accel-pub")
	accelPubType := r.Header.Get("x-rpc-sec-dbcs-accel-pub-type")
	accelPubSig := r.Header.Get("x-rpc-sec-dbcs-accel-pub-sig")

	// Parse hardware key for verification
	hwKey, err := parseAndValidateKey(string(hwKeyInfo.Key), string(hwKeyInfo.Type), "hardware key")
	if err != nil {
		errorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Verify acceleration key is signed by hardware key
	if err := verifySignedData(hwKey, accelPub, accelPubSig); err != nil {
		errorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Generate and store acceleration key
	accelKeyId, err := generateRandomString(16)
	if err != nil {
		errorResponse(w, "Failed to generate key ID", http.StatusInternalServerError)
		return
	}

	accelKeys.Set(accelKeyId, PublicKeyInfo{
		Key:  []byte(accelPub),
		Type: KeyType(strings.ToLower(accelPubType)),
	}, cache.DefaultExpiration)

	// Use the newly registered key to verify the request
	handleRegularRequestWithKey(w, r, accelPub, accelPubType, accelKeyId)
}

func handleRegularRequestWithKey(w http.ResponseWriter, r *http.Request, keyData string, keyType string, keyId string) {
	dataSig := r.Header.Get("x-rpc-sec-dbcs-data-sig")
	data := r.Header.Get("x-rpc-sec-dbcs-data")

	if dataSig == "" || data == "" {
		errorResponse(w, "Missing required headers", http.StatusBadRequest)
		return
	}

	// Parse and validate acceleration key
	accelKey, err := parseAndValidateKey(keyData, keyType, "acceleration key")
	if err != nil {
		errorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Verify request is signed by acceleration key
	if err := verifySignedData(accelKey, data, dataSig); err != nil {
		errorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// If this is a new key registration, include the key ID in response
	if keyId != "" {
		w.Header().Set("x-rpc-sec-dbcs-accel-pub-id", keyId)
	}

	setCORSHeaders(w)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"authenticated": true})
}

func handleRegularRequest(w http.ResponseWriter, r *http.Request) {
	accelPubId := r.Header.Get("x-rpc-sec-dbcs-accel-pub-id")
	if accelPubId == "" {
		errorResponse(w, "Missing acceleration key ID", http.StatusBadRequest)
		return
	}

	// Get acceleration key
	accelKeyInfo, found := accelKeys.Get(accelPubId)
	if !found {
		errorResponse(w, "Invalid acceleration key ID", http.StatusUnauthorized)
		return
	}
	keyInfo := accelKeyInfo.(PublicKeyInfo)

	handleRegularRequestWithKey(w, r, string(keyInfo.Key), string(keyInfo.Type), "")
}

func authenticatedHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		errorResponse(w, "Invalid authorization header", http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Verify token first
	tokenInfo, found := tokensCache.Get(token)
	if !found {
		errorResponse(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	hwKeyInfo := tokenInfo.(PublicKeyInfo)

	// Route to appropriate handler based on presence of headers
	if r.Header.Get("x-rpc-sec-dbcs-accel-pub") != "" {
		handleAccelKeyRegistration(w, r, hwKeyInfo)
		return
	}

	if r.Header.Get("x-rpc-sec-dbcs-accel-pub-id") != "" {
		handleRegularRequest(w, r)
		return
	}

	errorResponse(w, "Invalid request: missing either acceleration key or key ID", http.StatusBadRequest)
}

func main() {
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/authenticated", authenticatedHandler)
	log.Fatal(http.ListenAndServe(":28280", nil))
}
