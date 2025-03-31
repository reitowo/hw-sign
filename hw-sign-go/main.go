package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
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
	KeyTypeECDH    KeyType = "ecdh"
)

type PublicKeyInfo struct {
	Key  []byte
	Type KeyType
}

// UnifiedKeyInfo combines both asymmetric and symmetric key information
type UnifiedKeyInfo struct {
	PublicKey     []byte      // Public key for asymmetric crypto
	KeyType       KeyType     // The type of key (ecdsa, rsa-pss, ed25519)
	SymmetricKey  []byte      // AES-256 key for symmetric encryption (if available)
	ServerPrivKey interface{} // Server's private key for ECDH (if applicable)
}

var (
	usersCache  = cache.New(3*time.Hour, 10*time.Minute) // Cache for user data
	accelKeys   = cache.New(3*time.Hour, 10*time.Minute) // Cache for unified acceleration keys
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

	case string(KeyTypeECDH):
		// Handle ECDH public keys
		curve := ecdh.P256()

		// Try to handle the key directly first
		pubKey, err := curve.NewPublicKey(decoded)
		if err == nil {
			return pubKey, nil
		}

		// If direct import fails, try to handle different formats
		if len(decoded) == 65 && decoded[0] == 0x04 {
			// This is a raw uncompressed point format (0x04 || x || y)
			// ECDH.NewPublicKey expects just raw bytes, so try using the raw x,y coordinates
			x := new(big.Int).SetBytes(decoded[1:33])
			y := new(big.Int).SetBytes(decoded[33:65])

			// Convert to appropriate format for ECDH - first make sure it's on the curve
			if !elliptic.P256().IsOnCurve(x, y) {
				return nil, fmt.Errorf("point is not on P-256 curve")
			}

			// Marshal in the format ECDH expects
			rawKey := elliptic.Marshal(elliptic.P256(), x, y)
			return curve.NewPublicKey(rawKey)
		}

		// Try PKIX format
		key, err := x509.ParsePKIXPublicKey(decoded)
		if err == nil {
			// If it's an ECDSA key, we can convert to ECDH format
			if ecKey, ok := key.(*ecdsa.PublicKey); ok {
				if ecKey.Curve == elliptic.P256() {
					// Convert to uncompressed format
					rawKey := elliptic.Marshal(ecKey.Curve, ecKey.X, ecKey.Y)
					return curve.NewPublicKey(rawKey)
				}
			}
		}
		return nil, fmt.Errorf("invalid or unsupported ECDH key format: %v", err)
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

// Function to parse ECDH public key from raw bytes
func parseECDHPublicKey(data []byte) (*ecdh.PublicKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty public key data")
	}

	// Try to parse it as a raw X.509 DER key first
	curve := ecdh.P256()
	return curve.NewPublicKey(data)
}

// Function to generate a new ECDH key pair
func generateECDHKeyPair() (*ecdh.PrivateKey, error) {
	curve := ecdh.P256()
	return curve.GenerateKey(rand.Reader)
}

// Function to decrypt data with AES-GCM
func decryptWithAES(symmetricKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 12+16 { // 12 bytes nonce + at least 16 bytes of ciphertext (including tag)
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce from the first 12 bytes
	nonce := ciphertext[:12]
	ciphertext = ciphertext[12:]

	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// Compute shared secret from ECDH key exchange
func computeSharedSecret(privateKey *ecdh.PrivateKey, publicKey *ecdh.PublicKey) ([]byte, error) {
	sharedSecret, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}

	// Derive a suitable AES key from the shared secret
	hash := sha256.Sum256(sharedSecret)
	return hash[:], nil // Use the SHA-256 hash (32 bytes) as AES-256 key
}

// Add CORS headers helper function
func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-rpc-sec-dbcs-hw-pub, x-rpc-sec-dbcs-hw-pub-type, x-rpc-sec-dbcs-accel-pub, x-rpc-sec-dbcs-accel-pub-type, x-rpc-sec-dbcs-accel-pub-sig, x-rpc-sec-dbcs-data, x-rpc-sec-dbcs-data-sig, x-rpc-sec-dbcs-accel-pub-id, x-rpc-sec-dbcs-data-enc")
	w.Header().Set("Access-Control-Expose-Headers", "x-rpc-sec-dbcs-accel-pub-id, x-rpc-sec-dbcs-accel-pub")
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

// Central handler for both asymmetric and symmetric key registration
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

	// Generate key ID
	accelKeyId, err := generateRandomString(16)
	if err != nil {
		errorResponse(w, "Failed to generate key ID", http.StatusInternalServerError)
		return
	}

	// For ECDH key types, save hardware key for data verification
	isECDH := strings.ToLower(accelPubType) == string(KeyTypeECDH)

	// Prepare the unified key info - for ECDH, store hardware key for data verification
	unifiedKey := UnifiedKeyInfo{
		PublicKey: []byte(accelPub),
		KeyType:   KeyType(strings.ToLower(accelPubType)),
	}

	// For ECDH key types, perform key exchange and compute shared secret
	if isECDH {
		// Parse client's ECDH public key
		clientECDHPub, err := parsePublicKey(accelPub, string(KeyTypeECDH))
		if err != nil {
			errorResponse(w, fmt.Sprintf("Invalid ECDH public key: %v", err), http.StatusBadRequest)
			return
		}

		// Generate server's ECDH key pair
		serverECDHPriv, err := generateECDHKeyPair()
		if err != nil {
			errorResponse(w, "Failed to generate server ECDH key", http.StatusInternalServerError)
			return
		}

		// Export server's public key for the client
		serverPubKeyBytes := serverECDHPriv.PublicKey().Bytes()
		serverPubKeyBase64 := base64.StdEncoding.EncodeToString(serverPubKeyBytes)

		// Set the server's public key in the response header
		w.Header().Set("x-rpc-sec-dbcs-accel-pub", serverPubKeyBase64)

		// Compute the shared secret
		clientPubKey, ok := clientECDHPub.(*ecdh.PublicKey)
		if !ok {
			errorResponse(w, "Invalid ECDH public key type", http.StatusBadRequest)
			return
		}

		sharedSecret, err := computeSharedSecret(serverECDHPriv, clientPubKey)
		if err != nil {
			errorResponse(w, fmt.Sprintf("Failed to compute shared secret: %v", err), http.StatusInternalServerError)
			return
		}

		// Save the symmetric key in the unified key info
		unifiedKey.SymmetricKey = sharedSecret
		unifiedKey.ServerPrivKey = serverECDHPriv
	}

	// Store the unified key with its ID
	accelKeys.Set(accelKeyId, unifiedKey, cache.DefaultExpiration)

	// Set the key ID in the response header
	w.Header().Set("x-rpc-sec-dbcs-accel-pub-id", accelKeyId)

	// For ECDH key exchange, validate request data using hardware key for this first request
	if isECDH {
		data := r.Header.Get("x-rpc-sec-dbcs-data")
		dataSig := r.Header.Get("x-rpc-sec-dbcs-data-sig")

		// Verify that we have the data and signature
		if data == "" || dataSig == "" {
			errorResponse(w, "Missing data or signature for verification", http.StatusBadRequest)
			return
		}

		// Verify the data signature using the hardware key
		if err := verifySignedData(hwKey, data, dataSig); err != nil {
			errorResponse(w, fmt.Sprintf("Failed to verify data signature: %v", err), http.StatusUnauthorized)
			return
		}

		// Data validation succeeded
		setCORSHeaders(w)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"authenticated": true})
	} else {
		// For regular asymmetric keys, verify with the acceleration key
		handleRequest(w, r, unifiedKey)
	}
}

// Single handler for all authenticated requests
func handleRequest(w http.ResponseWriter, r *http.Request, keyInfo UnifiedKeyInfo) {
	// Check for encrypted data (symmetric) first
	encryptedData := r.Header.Get("x-rpc-sec-dbcs-data-enc")
	if encryptedData != "" && keyInfo.SymmetricKey != nil {
		data := r.Header.Get("x-rpc-sec-dbcs-data")

		// Handle symmetric encryption case
		encBytes, err := base64.StdEncoding.DecodeString(encryptedData)
		if err != nil {
			errorResponse(w, "Invalid encrypted data format", http.StatusBadRequest)
			return
		}

		decrypted, err := decryptWithAES(keyInfo.SymmetricKey, encBytes)
		if err != nil {
			errorResponse(w, fmt.Sprintf("Failed to decrypt data: %v", err), http.StatusBadRequest)
			return
		}

		if !bytes.Equal(decrypted, []byte(data)) {
			errorResponse(w, "Decrypted data does not match expected data", http.StatusUnauthorized)
			return
		}

		// Symmetric decryption succeeded
		log.Printf("Symmetric auth successful: %s", string(decrypted))
	} else {
		// Check for signed data (asymmetric)
		dataSig := r.Header.Get("x-rpc-sec-dbcs-data-sig")
		data := r.Header.Get("x-rpc-sec-dbcs-data")

		if dataSig == "" || data == "" {
			errorResponse(w, "Missing required headers for asymmetric verification", http.StatusBadRequest)
			return
		}

		// Parse and validate acceleration public key
		accelKey, err := parseAndValidateKey(string(keyInfo.PublicKey), string(keyInfo.KeyType), "acceleration key")
		if err != nil {
			errorResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Verify request is signed by acceleration key
		if err := verifySignedData(accelKey, data, dataSig); err != nil {
			errorResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Asymmetric verification succeeded
		log.Printf("Asymmetric auth successful: %s", data)
	}

	// If authentication succeeded (either symmetric or asymmetric), return success
	setCORSHeaders(w)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"authenticated": true})
}

// Main authentication handler
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

	// Check if this is a key registration or using existing key
	if r.Header.Get("x-rpc-sec-dbcs-accel-pub") != "" {
		// This is a new key registration (either asymmetric or ECDH)
		handleAccelKeyRegistration(w, r, hwKeyInfo)
		return
	}

	// Check if this is using an existing key
	accelKeyId := r.Header.Get("x-rpc-sec-dbcs-accel-pub-id")
	if accelKeyId == "" {
		errorResponse(w, "Missing acceleration key ID", http.StatusBadRequest)
		return
	}

	// Get acceleration key
	keyInfo, found := accelKeys.Get(accelKeyId)
	if !found {
		errorResponse(w, "Invalid acceleration key ID", http.StatusUnauthorized)
		return
	}
	unifiedKey := keyInfo.(UnifiedKeyInfo)

	// Handle the request with the existing key
	handleRequest(w, r, unifiedKey)
}

func main() {
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/authenticated", authenticatedHandler)
	log.Fatal(http.ListenAndServe(":28280", nil))
}
