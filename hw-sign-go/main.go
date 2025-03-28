package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
)

type PublicKeyStore struct {
	mu        sync.Mutex
	publicKey *ecdsa.PublicKey
}

var keyStore = &PublicKeyStore{}

func registerPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	keyBytes, err := base64.StdEncoding.DecodeString(payload.PublicKey)
	if err != nil {
		http.Error(w, "Invalid public key format", http.StatusBadRequest)
		return
	}

	pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		http.Error(w, "Failed to parse public key", http.StatusBadRequest)
		return
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		http.Error(w, "Public key is not ECDSA", http.StatusBadRequest)
		return
	}

	keyStore.mu.Lock()
	keyStore.publicKey = ecdsaPubKey
	keyStore.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Public key registered successfully")
}

func verifyRequestHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	sigBytes, err := base64.StdEncoding.DecodeString(payload.Signature)
	if err != nil {
		http.Error(w, "Invalid signature format", http.StatusBadRequest)
		return
	}

	hash := sha256.Sum256([]byte(payload.Message))

	keyStore.mu.Lock()
	defer keyStore.mu.Unlock()
	if keyStore.publicKey == nil {
		http.Error(w, "No public key registered", http.StatusBadRequest)
		return
	}

	if !ecdsa.VerifyASN1(keyStore.publicKey, hash[:], sigBytes) {
		http.Error(w, "Signature verification failed", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Request verified successfully")
}

func main() {
	http.HandleFunc("/register", registerPublicKeyHandler)
	http.HandleFunc("/verify", verifyRequestHandler)

	log.Println("Server is running on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
