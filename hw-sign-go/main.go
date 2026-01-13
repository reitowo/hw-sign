package main

import (
	"log"
	"net/http"
)

func main() {
	// User authentication endpoints
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/authenticated", authenticatedHandler)

	// TPM attestation endpoints
	http.HandleFunc("/verify-tpm-chain", verifyTPMChainHandler)
	http.HandleFunc("/verify-key-attestation", verifyKeyAttestationHandler)

	// AIK registration (MakeCredential/ActivateCredential) endpoints
	http.HandleFunc("/aik-challenge", aikChallengeHandler)
	http.HandleFunc("/aik-activate", aikActivateHandler)

	debugLog("main", "Server starting on port 28280")
	debugLog("main", "AIK endpoints: /verify-tpm-chain, /verify-key-attestation, /aik-challenge, /aik-activate")
	log.Fatal(http.ListenAndServe(":28280", nil))
}
