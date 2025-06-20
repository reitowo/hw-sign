package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// Test data structures
type TestData struct {
	Timestamp string
	RandHex   string
	Combined  string
}

// Helper function to generate P-256 key pair (used for both hardware and acceleration keys)
func generateP256KeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

// Helper function to generate test data
func generateTestData() *TestData {
	timestamp := fmt.Sprintf("%d", time.Now().UnixNano())
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	randHex := hex.EncodeToString(randBytes)

	return &TestData{
		Timestamp: timestamp,
		RandHex:   randHex,
		Combined:  timestamp + "-" + randHex,
	}
}

// Single comprehensive benchmark test for the complete cryptographic workflow
func BenchmarkCompleteWorkflow(b *testing.B) {
	b.Logf("Starting comprehensive cryptographic workflow benchmark")

	for i := 0; i < b.N; i++ {
		// Step 1: Prepare keys - create hw key pair (ecdsa-p256)
		hwPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			b.Fatal("Failed to generate hardware key pair:", err)
		}
		hwPub := &hwPriv.PublicKey

		// Step 1: Create accel key pair (P-256 for both signing and ECDH)
		accelPriv, accelPub, err := generateP256KeyPair()
		if err != nil {
			b.Fatal("Failed to generate acceleration key pair:", err)
		}

		// Step 2: Sign accel pub by hw priv
		accelPubBytes := elliptic.Marshal(elliptic.P256(), accelPub.X, accelPub.Y)
		r, s, err := ecdsa.Sign(rand.Reader, hwPriv, accelPubBytes[:])
		if err != nil {
			b.Fatal("Failed to sign acceleration public key:", err)
		}

		// Step 3: Sign data (timestamp-randhex) by accel priv
		testData := generateTestData()
		dataHash := sha256.Sum256([]byte(testData.Combined))
		dataR, dataS, err := ecdsa.Sign(rand.Reader, accelPriv, dataHash[:])
		if err != nil {
			b.Fatal("Failed to sign test data:", err)
		}

		// Step 4: Server verify accel pub by hw pub
		if !ecdsa.Verify(hwPub, accelPubBytes[:], r, s) {
			b.Fatal("Failed to verify acceleration public key signature")
		}

		// Step 5: Server verify data sig by accel pub
		if !ecdsa.Verify(accelPub, dataHash[:], dataR, dataS) {
			b.Fatal("Failed to verify data signature")
		}

		// Step 6: Create server ecdh-p256 key pair and do key exchange with accel pub
		// Convert to ECDH format
		accelPubECDHBytes := elliptic.Marshal(elliptic.P256(), accelPub.X, accelPub.Y)
		curve := ecdh.P256()
		clientECDHPub, err := curve.NewPublicKey(accelPubECDHBytes)
		if err != nil {
			b.Fatal("Failed to create client ECDH public key:", err)
		}

		// Generate server ECDH key pair
		serverECDHPriv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal("Failed to generate server ECDH key pair:", err)
		}

		// Perform key exchange
		sharedSecret, err := serverECDHPriv.ECDH(clientECDHPub)
		if err != nil {
			b.Fatal("Failed to perform ECDH key exchange:", err)
		}

		// Verify we got a valid shared secret
		if len(sharedSecret) == 0 {
			b.Fatal("Empty shared secret from ECDH")
		}

		// Log progress every 100 iterations for longer benchmarks
		if (i+1)%100 == 0 {
			b.Logf("Completed %d iterations successfully", i+1)
		}
	}
}

// Single comprehensive test for the complete cryptographic workflow
func TestCompleteWorkflow(t *testing.T) {
	t.Logf("Starting comprehensive cryptographic workflow test")

	// Step 1: Prepare keys - create hw key pair (ecdsa-p256)
	t.Log("Step 1: Generating hardware key pair (ECDSA P-256)")
	hwPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("Failed to generate hardware key pair:", err)
	}
	hwPub := &hwPriv.PublicKey
	t.Logf("Hardware P-256 public key: %s", base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), hwPub.X, hwPub.Y)))

	// Step 1: Create accel key pair (P-256 for both signing and ECDH)
	t.Log("Step 1: Generating acceleration key pair (P-256)")
	accelPriv, accelPub, err := generateP256KeyPair()
	if err != nil {
		t.Fatal("Failed to generate acceleration key pair:", err)
	}
	t.Logf("Acceleration P-256 public key: %s", base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), accelPub.X, accelPub.Y)))

	// Step 2: Sign accel pub by hw priv
	t.Log("Step 2: Signing acceleration public key with hardware private key")
	accelPubBytes := elliptic.Marshal(elliptic.P256(), accelPub.X, accelPub.Y)
	accelPubHash := sha256.Sum256(accelPubBytes)
	r, s, err := ecdsa.Sign(rand.Reader, hwPriv, accelPubHash[:])
	if err != nil {
		t.Fatal("Failed to sign acceleration public key:", err)
	}
	t.Logf("Acceleration public key signature: r=%s", r.String())

	// Step 3: Sign data (timestamp-randhex) by accel priv
	t.Log("Step 3: Generating test data and signing with acceleration private key")
	testData := generateTestData()
	t.Logf("Test data: %s", testData.Combined)
	dataHash := sha256.Sum256([]byte(testData.Combined))
	dataR, dataS, err := ecdsa.Sign(rand.Reader, accelPriv, dataHash[:])
	if err != nil {
		t.Fatal("Failed to sign test data:", err)
	}
	t.Logf("Data signature created successfully")

	// Step 4: Server verify accel pub by hw pub
	t.Log("Step 4: Server verifying acceleration public key signature")
	if !ecdsa.Verify(hwPub, accelPubHash[:], r, s) {
		t.Fatal("Failed to verify acceleration public key signature")
	}
	t.Log("✓ Acceleration public key signature verified successfully")

	// Step 5: Server verify data sig by accel pub
	t.Log("Step 5: Server verifying data signature")
	if !ecdsa.Verify(accelPub, dataHash[:], dataR, dataS) {
		t.Fatal("Failed to verify data signature")
	}
	t.Log("✓ Data signature verified successfully")

	// Step 6: Create server ecdh-p256 key pair and do key exchange with accel pub
	t.Log("Step 6: Performing ECDH key exchange")

	// Convert to ECDH format
	accelPubECDHBytes := elliptic.Marshal(elliptic.P256(), accelPub.X, accelPub.Y)
	curve := ecdh.P256()
	clientECDHPub, err := curve.NewPublicKey(accelPubECDHBytes)
	if err != nil {
		t.Fatal("Failed to create client ECDH public key:", err)
	}

	// Generate server ECDH key pair
	serverECDHPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("Failed to generate server ECDH key pair:", err)
	}

	serverECDHPub, _ := x509.MarshalPKIXPublicKey(serverECDHPriv.PublicKey())
	t.Logf("Server ECDH public key: %s", base64.StdEncoding.EncodeToString(serverECDHPub))

	// Perform key exchange
	sharedSecret, err := serverECDHPriv.ECDH(clientECDHPub)
	if err != nil {
		t.Fatal("Failed to perform ECDH key exchange:", err)
	}

	// Verify we got a valid shared secret
	if len(sharedSecret) == 0 {
		t.Fatal("Empty shared secret from ECDH")
	}
	t.Logf("✓ ECDH key exchange successful! Shared secret length: %d bytes", len(sharedSecret))
	t.Logf("Shared secret: %s", base64.StdEncoding.EncodeToString(sharedSecret))

	t.Log("🎉 Complete cryptographic workflow test passed successfully!")
}

// Performance comparison test
func TestPerformanceComparison(t *testing.T) {
	const iterations = 100

	t.Run("P256Operations", func(t *testing.T) {
		// Time key generation
		start := time.Now()
		for i := 0; i < iterations; i++ {
			_, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
		}
		keyGenDuration := time.Since(start)

		// Time signing operations
		hwPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		testData := []byte("performance test data")
		hash := sha256.Sum256(testData)

		start = time.Now()
		for i := 0; i < iterations; i++ {
			_, _, err := ecdsa.Sign(rand.Reader, hwPriv, hash[:])
			if err != nil {
				t.Fatal(err)
			}
		}
		signDuration := time.Since(start)

		// Time verification operations
		r, s, _ := ecdsa.Sign(rand.Reader, hwPriv, hash[:])
		start = time.Now()
		for i := 0; i < iterations; i++ {
			if !ecdsa.Verify(&hwPriv.PublicKey, hash[:], r, s) {
				t.Fatal("verification failed")
			}
		}
		verifyDuration := time.Since(start)

		// Time ECDH operations
		curve := ecdh.P256()
		start = time.Now()
		for i := 0; i < iterations; i++ {
			priv1, _ := curve.GenerateKey(rand.Reader)
			priv2, _ := curve.GenerateKey(rand.Reader)
			_, err := priv1.ECDH(priv2.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
		}
		ecdhDuration := time.Since(start)

		// Report results
		t.Logf("P-256 Performance Results (%d iterations):", iterations)
		t.Logf("Key generation: %v (avg: %v)", keyGenDuration, keyGenDuration/iterations)
		t.Logf("Signing: %v (avg: %v)", signDuration, signDuration/iterations)
		t.Logf("Verification: %v (avg: %v)", verifyDuration, verifyDuration/iterations)
		t.Logf("ECDH: %v (avg: %v)", ecdhDuration, ecdhDuration/iterations)
	})
}

// Test ECDSA P-256 signature verification with provided test data
func TestECDSAP256SignatureVerification(t *testing.T) {
	t.Log("Testing ECDSA P-256 signature verification with provided test data")

	// Test data sets
	testCases := []struct {
		name         string
		publicKeyB64 string
		plaintextB64 string
		signatures   []string
	}{
		{
			name:         "Windows",
			publicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs7QlaLpB0jw6DQvyLyDtOqzvrrjHvrKqAnys6qgGyqozpku3tS/gwvcKNBDifyr05UYHYAcLzyLNJ57XYkPPiw==",
			plaintextB64: "1234567890==",
			signatures: []string{
				"YLvs+xya4PZU2/jz8saWk/tPlja4B9mkz6iDAHf1OfsMZDhtThpP5JMCtJociPp/sZGHq/4+LF5ndR4DYeCD6A==",
				"Mvm0l6My9Cz8wXea8XFuRTNqYpDQuu+1qNzJyyoOI/WFwYsm/782HyHC4OOanZYtCtK2yUuFEUhvrHC8UA37rA==",
				"1BYuwr05K8BC9YYScWwUSrQac71cmnj8so8Auukt2XiNm6o5R/ZauVdlzdCovLu9Y1EFYtfM4Ij0wSatXqMOcA==",
				"YFfguSt6i6zUZwiRGKfJeFoDeDa6ZZ2Iknx0NUBNjyX054MJFr/IolsyDUefv+206y8VRk+3vPFcdJBre3K76Q==",
			},
		},
		{
			name:         "macOS",
			publicKeyB64: "BJQ+7eXZcgPnI5P73nGlsgn3RCY1yLEhdA3KJNnrUbniC0LaSlUtMpaBhzeQjgRYZYi4wPSVfLJZ9T8Ao5CRai8=",
			plaintextB64: "1234567890==",
			signatures: []string{
				"MEUCIQDfWzCdfE50ZM/HsfO55PHIgqR5C+jg1WiwK1HVHLlSRQIgDnG2Xxhr4S+SWlHNWHgzaxeMVV02xjiLMlh6qAJFwJ0=",
				"MEUCIHQMI9V89fSU9leOGQLr7cCTY56Vuc44OkxpLVWZUmojAiEAtcrJp7E50Id6SdEqFVtstjUp+rpZSpu3Vzhgwff94+E=",
				"MEUCIFzPM6VC8fzEEX5wcq8D+LOQirjg1lDq7qqbo+i0P+dMAiEA4Spe3bGJdyTUGumjhc/Qosh9TDQnRkWQ9c0S2GwEFbA=",
			},
		},
		{
			name:         "Test3",
			publicKeyB64: "BGD4KpyqndHf5CTpAlZXTubZXaaoqac4LJ0QNUlS8rWjOwh8frmZTsAD1C6ps5iB5aZt5lc/X8LGgMu0334plGg=",
			plaintextB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEigUJp7M4QumQ7r+xgsQqgNCsxFVaOz30EslGdi+lmN0DcX7RKAHCldU96JRj4A/AKxYOeN/Fb7VdVb7Wy1w3dg==",
			signatures: []string{
				"MEYCIQDA5DNoHDj5vX6pvtxRcu8HJnB4sDE7tMvOkKz+F8roGAIhAPzSWhOtE4sT3nCF7rcH0SQXmGWwHbCgplOOnnQh+EmP",
			},
		},
	}

	for _, testCase := range testCases {
		t.Logf("Testing %s", testCase.name)

		// Parse the public key
		t.Logf("Step 1: Parsing ECDSA P-256 public key for %s", testCase.name)

		// Handle different key formats
		var publicKey interface{}
		var err error

		// Try parsing as standard PKIX first
		publicKey, err = parsePublicKey(testCase.publicKeyB64, "ecdsa-p256")
		if err != nil {
			// If PKIX parsing fails, try raw point format (second test case)
			t.Errorf("PKIX parsing failed, trying raw point format: %v", err)
			return
		}

		ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("Parsed key is not ECDSA")
		}

		// Verify the curve
		if ecdsaKey.Curve != elliptic.P256() {
			t.Fatal("Key is not P-256 curve")
		}
		t.Logf("✓ Successfully parsed ECDSA P-256 public key for %s", testCase.name)

		// Test signature verification
		t.Logf("Step 2: Testing signature verification for %s", testCase.name)
		successCount := 0

		for i, sigB64 := range testCase.signatures {
			t.Logf("Testing signature %d: %s", i+1, sigB64)

			// Test using the main verifySignature function
			sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
			if err != nil {
				t.Errorf("Signature %d: Failed to decode signature: %v", i+1, err)
				continue
			}

			// Test using the main verifySignature function
			plainBytes, err := base64.StdEncoding.DecodeString(testCase.plaintextB64)
			if err != nil {
				t.Errorf("Signature %d: Failed to decode plaintextB64: %v", i+1, err)
				continue
			}

			// Verify using the main verifySignature function
			isValid := verifySignature(ecdsaKey, plainBytes, sigBytes)
			if isValid {
				t.Logf("✓ Signature %d verified successfully using verifySignature()", i+1)
				successCount++
			} else {
				t.Logf("✗ Signature %d failed verification using verifySignature()", i+1)
			}
		}

		t.Logf("Verification complete for %s: %d/%d signatures verified successfully", testCase.name, successCount, len(testCase.signatures))

		if successCount == 0 {
			t.Errorf("No signatures were successfully verified for %s - this may indicate a format issue", testCase.name)
		}
		t.Log("---")
	}
}

// Test RSA-2048 PSS signature verification with provided test data
func TestRSA2048PSSSignatureVerification(t *testing.T) {
	t.Log("Testing RSA-2048 PSS signature verification with provided test data")

	// Test data sets
	testCases := []struct {
		name         string
		publicKeyB64 string
		plaintextB64 string
		signatures   []string
	}{
		{
			name:         "Windows",
			publicKeyB64: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3n0ussUHvZhH1nBZiWEka3OL6OFo7P+jXn+oaOkG+mloxG7JMmnp943z/z5rWvUNN6kZz2ZZeQ+k+ezBZKKvvI+n4ZP5IkgJ/I1nPJzRLKb79OgZATm4Bo/hhQIDdmcsHid7Ajmh+9PoqUwOcX/pZ6FFdSvw/cQc2SB38b5ghpCx3dpUrAfZUV1U3eC1uUr7KiyRm8Dj1hPg4ri9jJhqB4ktr0FjLF43kUlBmZzoNsKq9WcxukF/aLAAgYBBC/d0/FIBRemAgLWJWNm5j45aE0dmKFLfoz2hH4TG4mXKNljbc6O0dQUnM+xMkmhC5FrAXOo3YtZw8ooaVeALPjBCWwIDAQAB",
			plaintextB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiH3HbpFLTj27XqObpHeJKXW6j3TTwhX2o2LAheAmtBQU/Qgn/4DTeMlRh0tweqFno1QLhQ2Nu4QlpqmsiegscQ==",
			signatures: []string{
				"eKpBcP5DFWEMONxKk8iAyb5pabBppZVgBBT2Ftm9OmtQkh+bCPLGJM6ILVi6Tg3VafbBFPjwNERXSwfXbUsiP6ca8ijXKp7aWYdBu4gtRVbzoj6gr47jo3A38cMbfcm7AEpQfboovT6f0wUPXfnN2vEocprJM8vZ/BC3fmjNL8R5m3+QRY+y9b3Mu8zCr/rTLw8aflz7b7r2Nb+a2kkFLgdk1tgJTz+/gUTU/N+txVDyjFcdhWLY18p96D0PDVCgvYXIFstbF+VVZVSTAOSlg1QCP/JCEgMWrt1/cLimLr8hFXv0kAL2x4/V7C6KkZk7Z7BFxQbP76lpXtp5rTJnZw==",
			},
		},
	}

	for _, testCase := range testCases {
		t.Logf("Testing %s", testCase.name)

		// Parse the public key
		t.Logf("Step 1: Parsing RSA-2048 PSS public key for %s", testCase.name)

		// Handle different key formats
		var publicKey interface{}
		var err error

		// Try parsing as standard PKIX first
		publicKey, err = parsePublicKey(testCase.publicKeyB64, "rsa-2048-pss")
		if err != nil {
			// If PKIX parsing fails, try raw point format (second test case)
			t.Errorf("PKIX parsing failed, trying raw point format: %v", err)
			return
		}

		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			t.Fatal("Parsed key is not RSA")
		}

		// Test signature verification
		t.Logf("Step 2: Testing signature verification for %s", testCase.name)
		successCount := 0

		for i, sigB64 := range testCase.signatures {
			t.Logf("Testing signature %d: %s", i+1, sigB64)

			// Test using the main verifySignature function
			sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
			if err != nil {
				t.Errorf("Signature %d: Failed to decode signature: %v", i+1, err)
				continue
			}

			// Test using the main verifySignature function
			plainBytes, err := base64.StdEncoding.DecodeString(testCase.plaintextB64)
			if err != nil {
				t.Errorf("Signature %d: Failed to decode plaintextB64: %v", i+1, err)
				continue
			}

			// Verify using the main verifySignature function
			isValid := verifySignature(rsaKey, plainBytes, sigBytes)
			if isValid {
				t.Logf("✓ Signature %d verified successfully using verifySignature()", i+1)
				successCount++
			} else {
				t.Logf("✗ Signature %d failed verification using verifySignature()", i+1)
			}
		}

		t.Logf("Verification complete for %s: %d/%d signatures verified successfully", testCase.name, successCount, len(testCase.signatures))

		if successCount == 0 {
			t.Errorf("No signatures were successfully verified for %s - this may indicate a format issue", testCase.name)
		}
		t.Log("---")
	}
}
