#pragma once

#include "test_client/types.h"
#include "test_client/tpm_attestation.hpp"
#include "test_client/unified_crypto_helper.hpp"

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include <ctime>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

// ============ Configuration ============
struct ClientConfig {
    std::string serverUrl = "http://localhost:28280";
    HardwareKeyType keyType = HardwareKeyType::ECDSA_P256;
    std::string username;
    std::string password;
    bool verbose = false;
    std::wstring aikName = L"HwSign_AIK";
    std::wstring aikUsageAuth; // optional PIN
    std::wstring aikNonce;     // optional nonce string (will be SHA1-hashed like PCPTool)

    static ClientConfig fromArgs(int argc, char* argv[]);
    static void printUsage(const char* programName);
};

inline void ClientConfig::printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " <command> [options]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  auth    Run authentication flow (register, login, authenticated requests)\n";
    std::cout << "  aik     Run AIK attestation flow (TPM cert chain, key attestation)\n";
    std::cout << "  both    Run both auth and AIK flows\n";
    std::cout << "  info    Show TPM information only\n\n";
    std::cout << "Options:\n";
    std::cout << "  -s, --server <url>     Server URL (default: http://localhost:28280)\n";
    std::cout << "  -k, --key <type>       Key type: ecdsa or rsa (default: ecdsa)\n";
    std::cout << "  -u, --username <name>  Username for auth (default: auto-generated)\n";
    std::cout << "  -p, --password <pwd>   Password for auth (default: testpass123)\n";
    std::cout << "  --aik-name <name>      AIK key name in PCP provider (default: HwSign_AIK)\n";
    std::cout << "  --aik-pin <pin>        AIK usageAuth/PIN (optional)\n";
    std::cout << "  --aik-nonce <nonce>    Nonce string for IdBinding (optional, PCPTool style)\n";
    std::cout << "  -v, --verbose          Enable verbose output\n";
    std::cout << "  -h, --help             Show this help message\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << programName << " auth\n";
    std::cout << "  " << programName << " auth -s http://api.example.com:8080 -k rsa\n";
    std::cout << "  " << programName << " aik -s http://localhost:28280\n";
    std::cout << "  " << programName << " both -u testuser -p mypassword\n";
}

inline ClientConfig ClientConfig::fromArgs(int argc, char* argv[]) {
    ClientConfig config;
    
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        
        if ((arg == "-s" || arg == "--server") && i + 1 < argc) {
            config.serverUrl = argv[++i];
        }
        else if ((arg == "-k" || arg == "--key") && i + 1 < argc) {
            std::string keyType = argv[++i];
            if (keyType == "rsa" || keyType == "RSA") {
                config.keyType = HardwareKeyType::RSA_2048_PSS;
            } else {
                config.keyType = HardwareKeyType::ECDSA_P256;
            }
        }
        else if ((arg == "-u" || arg == "--username") && i + 1 < argc) {
            config.username = argv[++i];
        }
        else if ((arg == "-p" || arg == "--password") && i + 1 < argc) {
            config.password = argv[++i];
        }
        else if (arg == "-v" || arg == "--verbose") {
            config.verbose = true;
        }
        else if (arg == "--aik-name" && i + 1 < argc) {
            std::string s = argv[++i];
            config.aikName = std::wstring(s.begin(), s.end());
        }
        else if (arg == "--aik-pin" && i + 1 < argc) {
            std::string s = argv[++i];
            config.aikUsageAuth = std::wstring(s.begin(), s.end());
        }
        else if (arg == "--aik-nonce" && i + 1 < argc) {
            std::string s = argv[++i];
            config.aikNonce = std::wstring(s.begin(), s.end());
        }
    }
    
    // Generate default username if not provided
    if (config.username.empty()) {
        std::string keyTypeStr = (config.keyType == HardwareKeyType::RSA_2048_PSS) ? "RSA" : "ECDSA";
        config.username = "testuser_" + keyTypeStr + "_" + std::to_string(std::time(nullptr));
    }
    
    // Default password
    if (config.password.empty()) {
        config.password = "testpass123";
    }
    
    return config;
}

class TestClient {
private:
    ClientConfig config_;
    std::string authToken_;
    std::string accelKeyId_;
    std::unique_ptr<UnifiedCryptoHelper> crypto_; // only used for auth flow; aik flow does not need it
    std::unique_ptr<TPMAttestationHelper> attestation_;
    bool aikCreated_ = false;

public:
    explicit TestClient(const ClientConfig& config) : config_(config) {
        std::cout << "\n==========================================" << std::endl;
        std::cout << "Initializing Test Client" << std::endl;
        std::cout << "==========================================" << std::endl;
        std::cout << "Server URL: " << config_.serverUrl << std::endl;
        std::cout << "Key Type: " << (config_.keyType == HardwareKeyType::RSA_2048_PSS ? "RSA-2048-PSS" : "ECDSA-P256") << std::endl;
        
        // Defer crypto helper initialization to auth flow only.
    }

    static std::string base64EncodeBytes(const std::vector<uint8_t>& data) {
        BIO* bio = BIO_new(BIO_s_mem());
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);
        BIO_write(bio, data.data(), (int)data.size());
        BIO_flush(bio);
        BUF_MEM* bufferPtr = nullptr;
        BIO_get_mem_ptr(bio, &bufferPtr);
        std::string result(bufferPtr->data, bufferPtr->length);
        BIO_free_all(bio);
        return result;
    }

    static std::vector<uint8_t> base64DecodeBytes(const std::string& input) {
        BIO* bio = BIO_new_mem_buf(input.data(), (int)input.length());
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);
        std::vector<uint8_t> result(input.length());
        int decodedLength = BIO_read(bio, result.data(), (int)input.length());
        BIO_free_all(bio);
        if (decodedLength < 0) decodedLength = 0;
        result.resize((size_t)decodedLength);
        return result;
    }

    // For /login in aik flow we just need a well-formed public key; no proof required by server.
    static std::string generateEphemeralLoginPubKeyBase64Pkix() {
        EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ec || !EC_KEY_generate_key(ec)) {
            if (ec) EC_KEY_free(ec);
            throw std::runtime_error("Failed to generate ephemeral ECDSA key");
        }
        EVP_PKEY* pkey = EVP_PKEY_new();
        if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
            if (pkey) EVP_PKEY_free(pkey);
            EC_KEY_free(ec);
            throw std::runtime_error("Failed to wrap ECDSA key");
        }
        // ec is now owned by pkey
        int len = i2d_PUBKEY(pkey, NULL);
        if (len <= 0) {
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to encode pubkey");
        }
        std::vector<uint8_t> der((size_t)len);
        unsigned char* p = der.data();
        i2d_PUBKEY(pkey, &p);
        EVP_PKEY_free(pkey);
        return base64EncodeBytes(der);
    }

    void ensureAuthCrypto() {
        if (!crypto_) {
            crypto_ = std::make_unique<UnifiedCryptoHelper>(config_.keyType);
            std::cout << "✓ Crypto helper initialized" << std::endl;
        }
    }

    // Initialize TPM attestation (only needed for AIK flow)
    bool initializeAttestation() {
        if (attestation_) return aikCreated_;
        
        std::cout << "\nInitializing TPM Attestation..." << std::endl;
        attestation_ = std::make_unique<TPMAttestationHelper>();
        
        if (attestation_->isInitialized()) {
            aikCreated_ = attestation_->createAIK(config_.aikName, config_.aikNonce, config_.aikUsageAuth);
            std::cout << "AIK creation: " << (aikCreated_ ? "✓ success" : "✗ failed") << std::endl;
        } else {
            std::cout << "✗ TPM Attestation initialization failed" << std::endl;
        }
        
        return aikCreated_;
    }

    const ClientConfig& getConfig() const { return config_; }
    bool hasAuthToken() const { return !authToken_.empty(); }

    bool testRegister() {
        std::cout << "\n=== Testing Registration ===" << std::endl;
        std::cout << "Username: " << config_.username << std::endl;
        std::cout << "Server: " << config_.serverUrl << std::endl;

        try {
            nlohmann::json payload = {
                {"username", config_.username},
                {"password", config_.password}
            };

            auto response = cpr::Post(
                cpr::Url{config_.serverUrl + "/register"},
                cpr::Body{payload.dump()},
                cpr::Header{{"Content-Type", "application/json"}}
            );

            std::cout << "Response status: " << response.status_code << std::endl;
            if (config_.verbose) {
                std::cout << "Response body: " << response.text << std::endl;
            }

            if (response.status_code == 201) {
                std::cout << "✓ Registration successful!" << std::endl;
                return true;
            }
            else {
                std::cout << "✗ Registration failed!" << std::endl;
                return false;
            }
        }
        catch (const std::exception& e) {
            std::cout << "✗ Registration error: " << e.what() << std::endl;
            return false;
        }
    }

    bool testLogin() {
        std::cout << "\n=== Testing Login ===" << std::endl;
        std::cout << "Username: " << config_.username << std::endl;

        try {
            nlohmann::json payload = {
                {"username", config_.username},
                {"password", config_.password}
            };

            std::string hwPubKey;
            std::string hwPubType;
            if (crypto_) {
                hwPubKey = crypto_->exportHardwarePublicKey();
                hwPubType = crypto_->getHardwareKeyType();
            } else {
                hwPubKey = generateEphemeralLoginPubKeyBase64Pkix();
                hwPubType = "ecdsa-p256";
            }

            if (config_.verbose) {
                std::cout << "Hardware public key (first 50 chars): " << hwPubKey.substr(0, 50) << "..." << std::endl;
            }
            std::cout << "Hardware key type: " << hwPubType << std::endl;

            auto response = cpr::Post(
                cpr::Url{config_.serverUrl + "/login"},
                cpr::Body{payload.dump()},
                cpr::Header{
                    {"Content-Type", "application/json"},
                    {"x-rpc-sec-bound-token-hw-pub", hwPubKey},
                    {"x-rpc-sec-bound-token-hw-pub-type", hwPubType}
                }
            );

            std::cout << "Response status: " << response.status_code << std::endl;
            if (config_.verbose) {
                std::cout << "Response body: " << response.text << std::endl;
            }

            if (response.status_code == 200) {
                auto respJson = nlohmann::json::parse(response.text);
                if (respJson.contains("token")) {
                    authToken_ = respJson["token"];
                    std::cout << "✓ Login successful! Token: " << authToken_.substr(0, 20) << "..." << std::endl;
                    return true;
                }
            }

            std::cout << "✗ Login failed!" << std::endl;
            return false;
        }
        catch (const std::exception& e) {
            std::cout << "✗ Login error: " << e.what() << std::endl;
            return false;
        }
    }

    bool testAuthenticated() {
        std::cout << "\n=== Testing Authenticated Request ===" << std::endl;

        if (authToken_.empty()) {
            std::cout << "✗ No auth token available!" << std::endl;
            return false;
        }

        try {
            // Generate timestamp and random hex using OpenSSL
            std::string timestamp = std::to_string(std::time(nullptr));

            // Generate 32 bytes of random data using OpenSSL
            unsigned char randomBytes[32];
            if (!RAND_bytes(randomBytes, 32)) {
                throw std::runtime_error("Failed to generate random bytes");
            }

            // Convert to hex string
            std::stringstream hexStream;
            hexStream << std::hex << std::setfill('0');
            for (int i = 0; i < 32; i++) {
                hexStream << std::setw(2) << static_cast<int>(randomBytes[i]);
            }
            std::string randomHex = hexStream.str();

            // Format request data
            std::string requestData = timestamp + "-" + randomHex;
            if (config_.verbose) {
                std::cout << "Request data: " << timestamp << "-" << randomHex.substr(0, 16) << "..." << std::endl;
            }

            cpr::Header requestHeaders;
            requestHeaders["Authorization"] = "Bearer " + authToken_;
            requestHeaders["x-rpc-sec-bound-token-data"] = requestData;

            if (accelKeyId_.empty()) {
                // First authenticated request - register ECDH acceleration key
                std::cout << "Registering new ECDH acceleration key..." << std::endl;

                std::string accelPub = crypto_->exportAccelPublicKeyPKIX();
                std::string accelPubType = crypto_->getAccelKeyType();
                std::string accelPubSig = crypto_->signDataWithHardwareKey(accelPub);
                std::string dataSig = crypto_->signDataWithAccelKey(requestData);

                requestHeaders["x-rpc-sec-bound-token-accel-pub"] = accelPub;
                requestHeaders["x-rpc-sec-bound-token-accel-pub-type"] = accelPubType;
                requestHeaders["x-rpc-sec-bound-token-accel-pub-sig"] = accelPubSig;
                requestHeaders["x-rpc-sec-bound-token-data-sig"] = dataSig;

                if (config_.verbose) {
                    std::cout << "Acceleration public key (first 50 chars): " << accelPub.substr(0, 50) << "..." << std::endl;
                    std::cout << "Acceleration key type: " << accelPubType << std::endl;
                }
            }
            else {
                // Subsequent requests - use HMAC with shared secret
                std::cout << "Using existing acceleration key ID: " << accelKeyId_ << std::endl;

                std::string dataSig = crypto_->signDataWithAccelKey(requestData);
                requestHeaders["x-rpc-sec-bound-token-accel-pub-id"] = accelKeyId_;
                requestHeaders["x-rpc-sec-bound-token-data-sig"] = dataSig;
            }

            auto response = cpr::Get(
                cpr::Url{config_.serverUrl + "/authenticated"},
                requestHeaders
            );

            std::cout << "Response status: " << response.status_code << std::endl;
            if (config_.verbose) {
                std::cout << "Response body: " << response.text << std::endl;
            }

            // Check for acceleration key ID in response headers
            auto it = response.header.find("x-rpc-sec-bound-token-accel-pub-id");
            if (it != response.header.end()) {
                accelKeyId_ = it->second;
                std::cout << "Received acceleration key ID: " << accelKeyId_ << std::endl;
            }

            // Check for server's ECDH public key in response headers
            auto serverPubIt = response.header.find("x-rpc-sec-bound-token-accel-pub");
            if (serverPubIt != response.header.end()) {
                if (config_.verbose) {
                    std::cout << "Received server ECDH public key" << std::endl;
                }
                // Establish shared secret for future HMAC operations
                crypto_->setSharedSecret(serverPubIt->second);
                std::cout << "Shared secret established for HMAC authentication" << std::endl;
            }

            if (response.status_code == 200) {
                std::cout << "✓ Authenticated request successful!" << std::endl;
                return true;
            }
            else {
                std::cout << "✗ Authenticated request failed!" << std::endl;
                return false;
            }
        }
        catch (const std::exception& e) {
            std::cout << "✗ Authenticated request error: " << e.what() << std::endl;
            return false;
        }
    }

    // Test TPM Certificate Chain collection and submission
    bool testTPMCertChain() {
        std::cout << "\n=== Testing TPM Certificate Chain Collection ===" << std::endl;

        if (!attestation_ || !attestation_->isInitialized()) {
            std::cout << "✗ TPM Attestation not available" << std::endl;
            return false;
        }

        try {
            // Get certificate chain JSON
            nlohmann::json certChain = attestation_->exportCertificateChainJson();
            if (config_.verbose) {
                std::cout << "Certificate chain collected:" << std::endl;
                std::cout << certChain.dump(2) << std::endl;
            } else {
                std::cout << "Certificate chain collected (use -v for details)" << std::endl;
            }

            // Submit to server for verification
            auto response = cpr::Post(
                cpr::Url{config_.serverUrl + "/verify-tpm-chain"},
                cpr::Body{certChain.dump()},
                cpr::Header{
                    {"Content-Type", "application/json"},
                    {"Authorization", "Bearer " + authToken_}
                }
            );

            std::cout << "Response status: " << response.status_code << std::endl;
            if (config_.verbose) {
                std::cout << "Response body: " << response.text << std::endl;
            }

            if (response.status_code == 200) {
                std::cout << "✓ TPM certificate chain verified successfully!" << std::endl;
                return true;
            } else {
                std::cout << "✗ TPM certificate chain verification failed" << std::endl;
                return false;
            }
        }
        catch (const std::exception& e) {
            std::cout << "✗ TPM certificate chain test error: " << e.what() << std::endl;
            return false;
        }
    }

    // AIK Registration (MakeCredential/ActivateCredential) - EKCert as trust root
    bool testAIKRegistration() {
        std::cout << "\n=== Testing AIK Registration (MakeCredential/ActivateCredential) ===" << std::endl;

        if (!attestation_ || !attestation_->isInitialized() || !aikCreated_) {
            std::cout << "✗ AIK not available" << std::endl;
            return false;
        }

        try {
            auto idBinding = attestation_->exportIdBinding();
            if (idBinding.empty()) {
                std::cout << "✗ id_binding is empty (CreateAIK did not produce IdBinding)" << std::endl;
                return false;
            }

            nlohmann::json req;
            req["cert_chain"] = attestation_->exportCertificateChainJson();
            req["id_binding"] = crypto_->base64Encode(idBinding);

            // Step 1: server creates activation blob (MakeCredential equivalent)
            auto resp1 = cpr::Post(
                cpr::Url{config_.serverUrl + "/aik-challenge"},
                cpr::Body{req.dump()},
                cpr::Header{
                    {"Content-Type", "application/json"},
                    {"Authorization", "Bearer " + authToken_},
                }
            );
            std::cout << "Challenge response status: " << resp1.status_code << std::endl;
            if (config_.verbose) {
                std::cout << "Challenge response body: " << resp1.text << std::endl;
            }
            if (resp1.status_code != 200) {
                std::cout << "✗ AIK challenge failed" << std::endl;
                return false;
            }

            auto json1 = nlohmann::json::parse(resp1.text);
            std::string challengeId = json1.value("challenge_id", "");
            std::string activationBlobB64 = json1.value("activation_blob", "");
            if (challengeId.empty() || activationBlobB64.empty()) {
                std::cout << "✗ Invalid challenge response" << std::endl;
                return false;
            }

            std::vector<uint8_t> activationBlob = crypto_->base64Decode(activationBlobB64);

            // Step 2: activate in TPM (client-side)
            std::vector<uint8_t> recoveredSecret = attestation_->activateAIK(activationBlob);
            std::cout << "✓ ActivateCredential returned secret size: " << recoveredSecret.size() << " bytes" << std::endl;

            // Step 3: send recovered secret back to server
            nlohmann::json req2;
            req2["challenge_id"] = challengeId;
            req2["secret"] = crypto_->base64Encode(recoveredSecret);

            auto resp2 = cpr::Post(
                cpr::Url{config_.serverUrl + "/aik-activate"},
                cpr::Body{req2.dump()},
                cpr::Header{
                    {"Content-Type", "application/json"},
                    {"Authorization", "Bearer " + authToken_},
                }
            );
            std::cout << "Activate response status: " << resp2.status_code << std::endl;
            if (config_.verbose) {
                std::cout << "Activate response body: " << resp2.text << std::endl;
            }
            if (resp2.status_code != 200) {
                std::cout << "✗ AIK activate verification failed" << std::endl;
                return false;
            }

            auto json2 = nlohmann::json::parse(resp2.text);
            bool verified = json2.value("verified", false);
            if (verified) {
                std::cout << "✓ AIK registration verified (EK + AIK are in same TPM)" << std::endl;
                return true;
            }
            std::cout << "✗ AIK registration not verified" << std::endl;
            return false;
        } catch (const std::exception& e) {
            std::cout << "✗ AIK registration error: " << e.what() << std::endl;
            return false;
        }
    }

    // Create a fresh TPM ECDSA key and certify it with AIK (TPM2_Certify)
    bool testNewEcdsaKeyAttestation() {
        std::cout << "\n=== Testing Key Attestation (New TPM ECDSA Key, Certified by AIK) ===" << std::endl;

        if (!attestation_ || !attestation_->isInitialized() || !aikCreated_) {
            std::cout << "✗ AIK not available for attestation" << std::endl;
            return false;
        }

        try {
            // Create fresh TPM ECDSA key (this is the key we want to attest)
            std::wstring keyName = L"HwSign_TpmEcdsa_" + std::to_wstring(std::time(nullptr));
            NCRYPT_KEY_HANDLE hKey = attestation_->createTpmEcdsaP256Key(keyName);

            // Generate key attestation (TPM2_Certify fallback path)
            auto attestResult = attestation_->generateKeyAttestation(hKey, "ecdsa-p256", {});
            
            if (!attestResult) {
                NCryptDeleteKey(hKey, 0);
                NCryptFreeObject(hKey);
                throw std::runtime_error("generateKeyAttestation failed");
            }

            const auto& attestBlob = *attestResult;

            // Build JSON payload for server verification
            nlohmann::json attestationJson = attestation_->exportKeyAttestationJson(attestBlob);
            attestationJson["aik_name"] = std::string(config_.aikName.begin(), config_.aikName.end());

            // Include IdBinding if present (from AIK creation with nonce)
            auto idBinding = attestation_->exportIdBinding();
            if (!idBinding.empty()) {
                attestationJson["id_binding"] = base64EncodeBytes(idBinding);
            }

            // Include full certificate chain for verification
            attestationJson["cert_chain"] = attestation_->exportCertificateChainJson();

            std::cout << "Key attestation generated (TPM2_Certify, AIK-certified new key):" << std::endl;
            std::cout << "  CertifyInfo: " << attestBlob.attestationBlob.size() << " bytes" << std::endl;
            std::cout << "  Signature:   " << attestBlob.signature.size() << " bytes" << std::endl;
            std::cout << "  Key blob:    " << attestBlob.keyBlob.size() << " bytes" << std::endl;
            std::cout << "  AIK name:    " << std::string(config_.aikName.begin(), config_.aikName.end()) << std::endl;

            // Submit to server for verification
            auto response = cpr::Post(
                cpr::Url{config_.serverUrl + "/verify-key-attestation"},
                cpr::Body{attestationJson.dump()},
                cpr::Header{
                    {"Content-Type", "application/json"},
                    {"Authorization", "Bearer " + authToken_}
                }
            );

            std::cout << "Response status: " << response.status_code << std::endl;
            if (config_.verbose) {
                std::cout << "Response body: " << response.text << std::endl;
            }

            // Cleanup key (this flow is “create once, attest once”)
            NCryptDeleteKey(hKey, 0);
            NCryptFreeObject(hKey);

            if (response.status_code == 200) {
                std::cout << "✓ Key attestation verified successfully!" << std::endl;
                std::cout << "✓ New TPM ECDSA key attested by AIK!" << std::endl;
                return true;
            } else {
                std::cout << "✗ Key attestation verification failed" << std::endl;
                return false;
            }
        }
        catch (const std::exception& e) {
            std::cout << "✗ Key attestation test error: " << e.what() << std::endl;
            return false;
        }
    }

    // Run authentication flow only
    bool runAuthFlow() {
        ensureAuthCrypto();
        std::string keyTypeStr = (config_.keyType == HardwareKeyType::RSA_2048_PSS) ? "RSA-2048-PSS" : "ECDSA-P256";

        std::cout << "\n==========================================" << std::endl;
        std::cout << "Authentication Flow Test" << std::endl;
        std::cout << keyTypeStr << " Hardware Key + ECDH-P256 Accel Key" << std::endl;
        std::cout << "==========================================" << std::endl;

        // Test 1: Register
        bool registerSuccess = testRegister();

        // Test 2: Login with hardware key
        bool loginSuccess = false;
        if (registerSuccess) {
            loginSuccess = testLogin();
        }

        // Test 3: Authenticated request (first time - register ECDH accel key)
        bool authSuccess1 = false;
        if (loginSuccess) {
            authSuccess1 = testAuthenticated();
        }

        // Test 4: Authenticated request (second time - use existing ECDH key)
        bool authSuccess2 = false;
        if (authSuccess1) {
            authSuccess2 = testAuthenticated();
        }

        // Test 5: Third authenticated request to verify ECDH key persistence
        bool authSuccess3 = false;
        if (authSuccess2) {
            authSuccess3 = testAuthenticated();
        }

        // Summary
        std::cout << "\n=== Auth Flow Results ===" << std::endl;
        std::cout << "Registration:            " << (registerSuccess ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "Login:                   " << (loginSuccess ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "Auth (new ECDH key):     " << (authSuccess1 ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "Auth (existing ECDH):    " << (authSuccess2 ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "Auth (ECDH persistent):  " << (authSuccess3 ? "✓ PASS" : "✗ FAIL") << std::endl;

        bool allPassed = registerSuccess && loginSuccess && authSuccess1 && authSuccess2 && authSuccess3;
        std::cout << "\nAuth Flow Result: " << (allPassed ? "✓ ALL PASSED" : "✗ SOME FAILED") << std::endl;

        return allPassed;
    }

    // Run AIK attestation flow only
    bool runAIKFlow() {
        std::cout << "\n==========================================" << std::endl;
        std::cout << "AIK (Attestation Identity Key) Flow Test" << std::endl;
        std::cout << "==========================================" << std::endl;

        // Initialize attestation if not already done
        if (!initializeAttestation()) {
            std::cout << "✗ Failed to initialize TPM attestation" << std::endl;
            return false;
        }

        // Need to login first if not already logged in
        if (!hasAuthToken()) {
            std::cout << "Need to authenticate first..." << std::endl;
            if (!testRegister() || !testLogin()) {
                std::cout << "✗ Authentication failed, cannot proceed with AIK flow" << std::endl;
                return false;
            }
        }

        // Step 1: Collect and upload EK material (EK cert(s), EICA cert(s), NV blobs).
        // This is used by the server to establish a trust root for EK and to build the certificate chain.
        bool tpmChainSuccess = testTPMCertChain();
        bool aikRegSuccess = false;
        if (tpmChainSuccess) {
            // Step 2: AIK registration handshake (MakeCredential/ActivateCredential).
            // Server uses EK public key (from EK cert) to encrypt a challenge; TPM can only decrypt it if EK+AIK are in the same TPM.
            aikRegSuccess = testAIKRegistration();
        }
        // Step 3: Create a NEW TPM ECDSA key and have AIK certify it via TPM2_Certify.
        // This is the actual “this key was generated inside TPM” proof.
        bool keyAttestSuccess = testNewEcdsaKeyAttestation();

        std::cout << "\n=== AIK Flow Results ===" << std::endl;
        std::cout << "TPM Certificate Chain: " << (tpmChainSuccess ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "AIK Registration:      " << (aikRegSuccess ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "Key Attestation:       " << (keyAttestSuccess ? "✓ PASS" : "✗ FAIL") << std::endl;

        bool allPassed = tpmChainSuccess && aikRegSuccess && keyAttestSuccess;
        std::cout << "\nAIK Flow Result: " << (allPassed ? "✓ ALL PASSED" : "✗ SOME FAILED") << std::endl;

        return allPassed;
    }

    // Show TPM information only
    void showTPMInfo() {
        std::cout << "\n==========================================" << std::endl;
        std::cout << "TPM Information" << std::endl;
        std::cout << "==========================================" << std::endl;

        if (!initializeAttestation()) {
            std::cout << "✗ Failed to initialize TPM attestation" << std::endl;
            return;
        }

        nlohmann::json certChain = attestation_->exportCertificateChainJson();
        std::cout << certChain.dump(2) << std::endl;
    }

    // Run both flows
    bool runBothFlows() {
        bool authSuccess = runAuthFlow();
        bool aikSuccess = runAIKFlow();

        std::cout << "\n==========================================" << std::endl;
        std::cout << "Overall Results" << std::endl;
        std::cout << "==========================================" << std::endl;
        std::cout << "Authentication Flow: " << (authSuccess ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "AIK Flow:           " << (aikSuccess ? "✓ PASS" : "✗ FAIL") << std::endl;

        return authSuccess && aikSuccess;
    }
};
