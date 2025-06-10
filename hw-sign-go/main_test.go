package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
	t.Logf("Server ECDH public key: %s", base64.StdEncoding.EncodeToString(serverECDHPriv.PublicKey().Bytes()))

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
