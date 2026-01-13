package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// ============ HTTP Utility Functions ============

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

// Extract and validate the authorization token
func extractAndValidateToken(r *http.Request) (string, error) {
	debugLog("tokenValidation", "Extracting token from Authorization header")
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("invalid authorization header")
	}
	return strings.TrimPrefix(authHeader, "Bearer "), nil
}

// ============ User Handlers ============

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

// ============ Dual-Purpose ECDSA/ECDH Functions ============

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

// ============ Acceleration Key Handlers ============

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

	// Step 1: Verify ECDSA signature of data, and convert the key to ECDH public key
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

// ============ TPM Attestation Handlers ============

// verifyTPMChainHandler handles TPM certificate chain verification requests
func verifyTPMChainHandler(w http.ResponseWriter, r *http.Request) {
	debugLog("verifyTPMChain", "Received TPM chain verification request from %s", r.RemoteAddr)
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

	// Parse the certificate chain
	var certChain TPMCertificateChain
	if err := json.NewDecoder(r.Body).Decode(&certChain); err != nil {
		errorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Verify the TPM certificate chain
	result := verifyTPMCertificateChain(certChain)

	// Store verification result if successful
	if result.Verified {
		verifiedTPMTokens.Set(token, result, cache.DefaultExpiration)
		debugLog("verifyTPMChain", "TPM verification successful for token, manufacturer: %s", result.TPMManufacturer)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// verifyKeyAttestationHandler handles key attestation verification requests
func verifyKeyAttestationHandler(w http.ResponseWriter, r *http.Request) {
	debugLog("verifyKeyAttestation", "Received key attestation verification request from %s", r.RemoteAddr)
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

	// Parse the attestation request
	var attestation KeyAttestationRequest
	if err := json.NewDecoder(r.Body).Decode(&attestation); err != nil {
		errorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Verify the key attestation
	result := verifyKeyAttestation(attestation)

	// Update token verification status if successful
	if result.KeyInTPM {
		if existingResult, found := verifiedTPMTokens.Get(token); found {
			existing := existingResult.(TPMVerificationResult)
			existing.KeyInTPM = true
			verifiedTPMTokens.Set(token, existing, cache.DefaultExpiration)
		} else {
			verifiedTPMTokens.Set(token, result, cache.DefaultExpiration)
		}
		debugLog("verifyKeyAttestation", "Key attestation successful for token")
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// ============ AIK Registration Handlers ============

// aikChallengeHandler creates an activation blob (MakeCredential-equivalent) from EKCert and IdBinding.
func aikChallengeHandler(w http.ResponseWriter, r *http.Request) {
	debugLog("aikChallenge", "Received AIK challenge request from %s", r.RemoteAddr)
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Validate token
	_, err := extractAndValidateToken(r)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req AikChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.IdBinding == "" {
		errorResponse(w, "Missing id_binding", http.StatusBadRequest)
		return
	}

	// IMPORTANT:
	// This challenge is the standard MakeCredential/ActivateCredential handshake.
	// The server MUST use the EK public key (ideally validated via EK certificate chain) to encrypt a challenge,
	// because only the TPM that owns the EK private key can decrypt it.
	//
	// Extract EK public key (RSA or ECC)
	ekPub, _, warnings, err := extractEkPublicKey(req.CertChain)
	if err != nil {
		errorResponse(w, fmt.Sprintf("EK required: %v", err), http.StatusBadRequest)
		return
	}
	debugLog("aikChallenge", "EK type: %s", ekPub.String())
	for _, wmsg := range warnings {
		debugLog("aikChallenge", "warning: %s", wmsg)
	}

	// Parse IdBinding and compute AIK Name
	idb, err := decodeBase64OrErr(req.IdBinding)
	if err != nil {
		errorResponse(w, "Invalid id_binding base64", http.StatusBadRequest)
		return
	}
	debugLog("aikChallenge", "IdBinding size: %d bytes", len(idb))

	aikPub, aikName, err := parseIdBindingAndComputeAikName(idb)
	if err != nil {
		errorResponse(w, fmt.Sprintf("Failed to parse id_binding: %v", err), http.StatusBadRequest)
		return
	}
	debugLog("aikChallenge", "AIK pub size: %d bytes, AIK name: %x", len(aikPub), aikName)

	// Server secret to be recovered by TPM (this is what we verify)
	expected := make([]byte, 16)
	if _, err := rand.Read(expected); err != nil {
		errorResponse(w, "Failed to generate secret", http.StatusInternalServerError)
		return
	}

	activationBlob, err := makeActivationBlob(ekPub, aikName, expected)
	if err != nil {
		errorResponse(w, fmt.Sprintf("Failed to create activation blob: %v", err), http.StatusInternalServerError)
		return
	}
	debugLog("aikChallenge", "Activation blob size: %d bytes", len(activationBlob))

	challengeID, err := generateRandomString(18)
	if err != nil {
		errorResponse(w, "Failed to generate challenge ID", http.StatusInternalServerError)
		return
	}
	aikChallenges.Set(challengeID, aikChallengeState{
		ExpectedSecret: expected,
		CreatedAt:      time.Now(),
	}, cache.DefaultExpiration)

	resp := AikChallengeResponse{
		ChallengeID:    challengeID,
		ActivationBlob: base64.StdEncoding.EncodeToString(activationBlob),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// aikActivateHandler verifies the recovered secret from TPM ActivateCredential.
func aikActivateHandler(w http.ResponseWriter, r *http.Request) {
	debugLog("aikActivate", "Received AIK activate request from %s", r.RemoteAddr)
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

	var req AikActivateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.ChallengeID == "" || req.Secret == "" {
		errorResponse(w, "Missing challenge_id or secret", http.StatusBadRequest)
		return
	}

	val, found := aikChallenges.Get(req.ChallengeID)
	if !found {
		errorResponse(w, "Unknown or expired challenge_id", http.StatusBadRequest)
		return
	}
	state := val.(aikChallengeState)

	secretBytes, err := decodeBase64OrErr(req.Secret)
	if err != nil {
		errorResponse(w, "Invalid secret base64", http.StatusBadRequest)
		return
	}
	if !bytes.Equal(secretBytes, state.ExpectedSecret) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"verified": false,
			"reason":   "secret mismatch",
		})
		return
	}

	// Mark token TPM-verified (AIK registered)
	if existing, ok := verifiedTPMTokens.Get(token); ok {
		ex := existing.(TPMVerificationResult)
		ex.AIKValid = true
		ex.Verified = true
		verifiedTPMTokens.Set(token, ex, cache.DefaultExpiration)
	} else {
		verifiedTPMTokens.Set(token, TPMVerificationResult{
			Verified:         true,
			AIKValid:         true,
			EKCertValid:      true,
			VerificationTime: time.Now().UTC().Format(time.RFC3339),
		}, cache.DefaultExpiration)
	}

	// One-time use
	aikChallenges.Delete(req.ChallengeID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"verified": true,
	})
}
