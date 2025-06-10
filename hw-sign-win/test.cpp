#include <iostream>
#include <string>
#include <vector>
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <ctime>
#include <memory>

class CryptoHelper {
private:
    EC_KEY* hwEcdsaKey_ = nullptr;
    EC_KEY* accelEcdhKey_ = nullptr;
    std::vector<uint8_t> sharedSecret_;
    std::string keyType_ = "ecdsa";

public:
    CryptoHelper() {
        // Initialize OpenSSL
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        
        // Generate ECDSA P-256 key for hardware key
        hwEcdsaKey_ = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!hwEcdsaKey_ || !EC_KEY_generate_key(hwEcdsaKey_)) {
            throw std::runtime_error("Failed to generate ECDSA hardware key");
        }
        
        // Generate ECDH P-256 key for acceleration key
        accelEcdhKey_ = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!accelEcdhKey_ || !EC_KEY_generate_key(accelEcdhKey_)) {
            throw std::runtime_error("Failed to generate ECDH acceleration key");
        }
        
        std::cout << "Generated ECDSA P-256 hardware key and ECDH P-256 acceleration key" << std::endl;
    }
    
    ~CryptoHelper() {
        if (hwEcdsaKey_) {
            EC_KEY_free(hwEcdsaKey_);
        }
        if (accelEcdhKey_) {
            EC_KEY_free(accelEcdhKey_);
        }
        EVP_cleanup();
        ERR_free_strings();
    }
    
    std::string base64Encode(const std::vector<uint8_t>& data) {
        BIO* bio = BIO_new(BIO_s_mem());
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);
        
        BIO_write(bio, data.data(), data.size());
        BIO_flush(bio);
        
        BUF_MEM* bufferPtr;
        BIO_get_mem_ptr(bio, &bufferPtr);
        
        std::string result(bufferPtr->data, bufferPtr->length);
        BIO_free_all(bio);
        
        return result;
    }
    
    std::vector<uint8_t> base64Decode(const std::string& input) {
        BIO* bio = BIO_new_mem_buf(input.data(), input.length());
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);
        
        std::vector<uint8_t> result(input.length());
        int decodedLength = BIO_read(bio, result.data(), input.length());
        BIO_free_all(bio);
        
        result.resize(decodedLength);
        return result;
    }
    
    std::string exportHardwarePublicKeyPKIX() {
        // Create EVP_PKEY from EC_KEY
        EVP_PKEY* pkey = EVP_PKEY_new();
        if (!pkey || !EVP_PKEY_set1_EC_KEY(pkey, hwEcdsaKey_)) {
            throw std::runtime_error("Failed to create EVP_PKEY for hardware key");
        }
        
        // Export to PKIX format
        BIO* bio = BIO_new(BIO_s_mem());
        if (!i2d_PUBKEY_bio(bio, pkey)) {
            BIO_free(bio);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to export hardware public key");
        }
        
        BUF_MEM* bufferPtr;
        BIO_get_mem_ptr(bio, &bufferPtr);
        
        std::vector<uint8_t> keyData(bufferPtr->data, bufferPtr->data + bufferPtr->length);
        
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        
        return base64Encode(keyData);
    }
    
    std::string exportAccelPublicKeyPKIX() {
        // Create EVP_PKEY from EC_KEY
        EVP_PKEY* pkey = EVP_PKEY_new();
        if (!pkey || !EVP_PKEY_set1_EC_KEY(pkey, accelEcdhKey_)) {
            throw std::runtime_error("Failed to create EVP_PKEY for accel key");
        }
        
        // Export to PKIX format
        BIO* bio = BIO_new(BIO_s_mem());
        if (!i2d_PUBKEY_bio(bio, pkey)) {
            BIO_free(bio);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to export acceleration public key");
        }
        
        BUF_MEM* bufferPtr;
        BIO_get_mem_ptr(bio, &bufferPtr);
        
        std::vector<uint8_t> keyData(bufferPtr->data, bufferPtr->data + bufferPtr->length);
        
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        
        return base64Encode(keyData);
    }
    
    std::string signDataWithHardwareKey(const std::string& data) {
        // Hash the data with SHA-256
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);
        
        // Sign the hash
        unsigned char signature[256];
        unsigned int sigLen;
        
        if (!ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, signature, &sigLen, hwEcdsaKey_)) {
            throw std::runtime_error("Failed to sign data with hardware key");
        }
        
        std::vector<uint8_t> sigVec(signature, signature + sigLen);
        return base64Encode(sigVec);
    }
    
    std::string signDataWithAccelKey(const std::string& data) {
        if (sharedSecret_.empty()) {
            // No shared secret yet, use ECDSA signing for initial request
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);
            
            unsigned char signature[256];
            unsigned int sigLen;
            
            if (!ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, signature, &sigLen, accelEcdhKey_)) {
                throw std::runtime_error("Failed to sign data with acceleration key");
            }
            
            std::vector<uint8_t> sigVec(signature, signature + sigLen);
            return base64Encode(sigVec);
        } else {
            // Use HMAC-SHA256 with shared secret
            return computeHMAC(data, sharedSecret_);
        }
    }
    
    std::string computeHMAC(const std::string& data, const std::vector<uint8_t>& key) {
        unsigned char result[EVP_MAX_MD_SIZE];
        unsigned int result_len;
        
        HMAC(EVP_sha256(), key.data(), key.size(),
             reinterpret_cast<const unsigned char*>(data.c_str()), data.length(),
             result, &result_len);
        
        std::vector<uint8_t> hmacVec(result, result + result_len);
        return base64Encode(hmacVec);
    }
    
    void setSharedSecret(const std::string& serverPubKeyBase64) {
        try {
            std::cout << "Setting up ECDH shared secret..." << std::endl;
            
            // Decode server's public key from base64
            std::vector<uint8_t> serverPubKeyBytes = base64Decode(serverPubKeyBase64);
            std::cout << "Decoded server public key, length: " << serverPubKeyBytes.size() << " bytes" << std::endl;
            
            // Create BIO from server's public key bytes
            BIO* bio = BIO_new_mem_buf(serverPubKeyBytes.data(), static_cast<int>(serverPubKeyBytes.size()));
            if (!bio) {
                throw std::runtime_error("Failed to create BIO from server public key");
            }
            
            // Try to parse as PKIX format first
            EVP_PKEY* serverPubKey = d2i_PUBKEY_bio(bio, nullptr);
            BIO_free(bio);
            
            if (!serverPubKey) {
                // If PKIX parsing failed, try raw uncompressed point format
                if (serverPubKeyBytes.size() == 65 && serverPubKeyBytes[0] == 0x04) {
                    std::cout << "Trying raw uncompressed point format..." << std::endl;
                    serverPubKey = createEVPKeyFromRawPoint(serverPubKeyBytes);
                } else {
                    throw std::runtime_error("Failed to parse server public key in any known format");
                }
            }
            
            if (!serverPubKey) {
                throw std::runtime_error("Failed to create server EVP_PKEY");
            }
            
            // Convert our ECDH key to EVP_PKEY format
            EVP_PKEY* clientPrivKey = EVP_PKEY_new();
            if (!clientPrivKey || !EVP_PKEY_set1_EC_KEY(clientPrivKey, accelEcdhKey_)) {
                EVP_PKEY_free(serverPubKey);
                if (clientPrivKey) EVP_PKEY_free(clientPrivKey);
                throw std::runtime_error("Failed to convert client ECDH key to EVP_PKEY");
            }
            
            // Perform ECDH key derivation
            sharedSecret_ = performECDHKeyDerivation(clientPrivKey, serverPubKey);
            
            // Cleanup
            EVP_PKEY_free(serverPubKey);
            EVP_PKEY_free(clientPrivKey);
            
            std::cout << "✓ ECDH shared secret established successfully, length: " << sharedSecret_.size() << " bytes" << std::endl;
            
        } catch (const std::exception& e) {
            sharedSecret_.clear();
            throw std::runtime_error(std::string("ECDH key exchange failed: ") + e.what());
        }
    }
    
    std::string getHardwareKeyType() const {
        return keyType_;
    }
    
    std::string getAccelKeyType() const {
        return "ecdh";  // ECDH type for acceleration key
    }
    
private:
    // Helper function to create EVP_PKEY from raw uncompressed point
    EVP_PKEY* createEVPKeyFromRawPoint(const std::vector<uint8_t>& rawPoint) {
        if (rawPoint.size() != 65 || rawPoint[0] != 0x04) {
            return nullptr;
        }
        
        // Create EC_KEY for P-256 curve
        EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ecKey) {
            return nullptr;
        }
        
        // Create point from raw coordinates
        const EC_GROUP* group = EC_KEY_get0_group(ecKey);
        EC_POINT* point = EC_POINT_new(group);
        if (!point) {
            EC_KEY_free(ecKey);
            return nullptr;
        }
        
        // Set point from uncompressed format
        if (!EC_POINT_oct2point(group, point, rawPoint.data(), rawPoint.size(), nullptr)) {
            EC_POINT_free(point);
            EC_KEY_free(ecKey);
            return nullptr;
        }
        
        // Set the public key point
        if (!EC_KEY_set_public_key(ecKey, point)) {
            EC_POINT_free(point);
            EC_KEY_free(ecKey);
            return nullptr;
        }
        
        // Convert to EVP_PKEY
        EVP_PKEY* pkey = EVP_PKEY_new();
        if (!pkey || !EVP_PKEY_set1_EC_KEY(pkey, ecKey)) {
            if (pkey) EVP_PKEY_free(pkey);
            EC_POINT_free(point);
            EC_KEY_free(ecKey);
            return nullptr;
        }
        
        // Cleanup intermediate objects
        EC_POINT_free(point);
        EC_KEY_free(ecKey);
        
        return pkey;
    }
    
    // Helper function to perform ECDH key derivation
    std::vector<uint8_t> performECDHKeyDerivation(EVP_PKEY* clientPrivKey, EVP_PKEY* serverPubKey) {
        // Create derivation context
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(clientPrivKey, nullptr);
        if (!ctx) {
            throw std::runtime_error("Failed to create ECDH context");
        }
        
        // Initialize derivation
        if (EVP_PKEY_derive_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize ECDH derivation");
        }
        
        // Set peer key
        if (EVP_PKEY_derive_set_peer(ctx, serverPubKey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to set ECDH peer key");
        }
        
        // Get shared secret length
        size_t secretLen = 0;
        if (EVP_PKEY_derive(ctx, nullptr, &secretLen) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to get ECDH secret length");
        }
        
        // Derive shared secret
        std::vector<uint8_t> secret(secretLen);
        if (EVP_PKEY_derive(ctx, secret.data(), &secretLen) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to derive ECDH shared secret");
        }
        
        // Cleanup and resize to actual length
        EVP_PKEY_CTX_free(ctx);
        secret.resize(secretLen);
        
        std::cout << "ECDH derivation completed, secret length: " << secretLen << " bytes" << std::endl;
        return secret;
    }
};

class TestClient {
private:
    std::string baseUrl_ = "http://localhost:28280";
    std::string authToken_;
    std::string accelKeyId_;
    CryptoHelper crypto_;
    
public:
    TestClient() {
        std::cout << "Initialized test client with base URL: " << baseUrl_ << std::endl;
    }
    
    bool testRegister(const std::string& username, const std::string& password) {
        std::cout << "\n=== Testing Registration ===" << std::endl;
        std::cout << "Username: " << username << std::endl;
        std::cout << "Password: " << password << std::endl;
        
        try {
            nlohmann::json payload = {
                {"username", username},
                {"password", password}
            };
            
            auto response = cpr::Post(
                cpr::Url{baseUrl_ + "/register"},
                cpr::Body{payload.dump()},
                cpr::Header{{"Content-Type", "application/json"}}
            );
            
            std::cout << "Response status: " << response.status_code << std::endl;
            std::cout << "Response body: " << response.text << std::endl;
            
            if (response.status_code == 201) {
                std::cout << "✓ Registration successful!" << std::endl;
                return true;
            } else {
                std::cout << "✗ Registration failed!" << std::endl;
                return false;
            }
        } catch (const std::exception& e) {
            std::cout << "✗ Registration error: " << e.what() << std::endl;
            return false;
        }
    }
    
    bool testLogin(const std::string& username, const std::string& password) {
        std::cout << "\n=== Testing Login ===" << std::endl;
        std::cout << "Username: " << username << std::endl;
        std::cout << "Password: " << password << std::endl;
        
        try {
            nlohmann::json payload = {
                {"username", username},
                {"password", password}
            };
            
            std::string hwPubKey = crypto_.exportHardwarePublicKeyPKIX();
            std::string hwPubType = crypto_.getHardwareKeyType();
            
            std::cout << "Hardware public key (first 50 chars): " << hwPubKey.substr(0, 50) << "..." << std::endl;
            std::cout << "Hardware key type: " << hwPubType << std::endl;
            
            auto response = cpr::Post(
                cpr::Url{baseUrl_ + "/login"},
                cpr::Body{payload.dump()},
                cpr::Header{
                    {"Content-Type", "application/json"},
                    {"x-rpc-sec-dbcs-hw-pub", hwPubKey},
                    {"x-rpc-sec-dbcs-hw-pub-type", hwPubType}
                }
            );
            
            std::cout << "Response status: " << response.status_code << std::endl;
            std::cout << "Response body: " << response.text << std::endl;
            
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
        } catch (const std::exception& e) {
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
            // Prepare request data (timestamp)
            std::string timestamp = std::to_string(std::time(nullptr));
            std::cout << "Request timestamp: " << timestamp << std::endl;
            
            cpr::Header requestHeaders;
            requestHeaders["Authorization"] = "Bearer " + authToken_;
            requestHeaders["x-rpc-sec-dbcs-data"] = timestamp;
            
            if (accelKeyId_.empty()) {
                // First authenticated request - register ECDH acceleration key
                std::cout << "Registering new ECDH acceleration key..." << std::endl;
                
                std::string accelPub = crypto_.exportAccelPublicKeyPKIX();
                std::string accelPubType = crypto_.getAccelKeyType();
                std::string accelPubSig = crypto_.signDataWithHardwareKey(accelPub);
                std::string dataSig = crypto_.signDataWithAccelKey(timestamp);
                
                requestHeaders["x-rpc-sec-dbcs-accel-pub"] = accelPub;
                requestHeaders["x-rpc-sec-dbcs-accel-pub-type"] = accelPubType;
                requestHeaders["x-rpc-sec-dbcs-accel-pub-sig"] = accelPubSig;
                requestHeaders["x-rpc-sec-dbcs-data-sig"] = dataSig;
                
                std::cout << "Acceleration public key (first 50 chars): " << accelPub.substr(0, 50) << "..." << std::endl;
                std::cout << "Acceleration key type: " << accelPubType << std::endl;
                std::cout << "Accel pub signature (first 20 chars): " << accelPubSig.substr(0, 20) << "..." << std::endl;
                std::cout << "Data signature (first 20 chars): " << dataSig.substr(0, 20) << "..." << std::endl;
            } else {
                // Subsequent requests - use HMAC with shared secret
                std::cout << "Using existing acceleration key ID with HMAC: " << accelKeyId_ << std::endl;
                
                std::string dataSig = crypto_.signDataWithAccelKey(timestamp);
                requestHeaders["x-rpc-sec-dbcs-accel-pub-id"] = accelKeyId_;
                requestHeaders["x-rpc-sec-dbcs-data-sig"] = dataSig;
                
                std::cout << "HMAC signature (first 20 chars): " << dataSig.substr(0, 20) << "..." << std::endl;
            }
            
            auto response = cpr::Get(
                cpr::Url{baseUrl_ + "/authenticated"},
                requestHeaders
            );
            
            std::cout << "Response status: " << response.status_code << std::endl;
            std::cout << "Response body: " << response.text << std::endl;
            
            // Check for acceleration key ID in response headers
            auto it = response.header.find("x-rpc-sec-dbcs-accel-pub-id");
            if (it != response.header.end()) {
                accelKeyId_ = it->second;
                std::cout << "Received acceleration key ID: " << accelKeyId_ << std::endl;
            }
            
            // Check for server's ECDH public key in response headers
            auto serverPubIt = response.header.find("x-rpc-sec-dbcs-accel-pub");
            if (serverPubIt != response.header.end()) {
                std::cout << "Received server ECDH public key (first 30 chars): " 
                         << serverPubIt->second.substr(0, 30) << "..." << std::endl;
                
                // Establish shared secret for future HMAC operations
                crypto_.setSharedSecret(serverPubIt->second);
                std::cout << "Shared secret established for HMAC authentication" << std::endl;
            }
            
            if (response.status_code == 200) {
                std::cout << "✓ Authenticated request successful!" << std::endl;
                return true;
            } else {
                std::cout << "✗ Authenticated request failed!" << std::endl;
                return false;
            }
        } catch (const std::exception& e) {
            std::cout << "✗ Authenticated request error: " << e.what() << std::endl;
            return false;
        }
    }
    
    void runFullTest() {
        std::cout << "=====================================" << std::endl;
        std::cout << "Hardware-Bound Authentication Test" << std::endl;
        std::cout << "ECDSA Hardware Key + ECDH Accel Key" << std::endl;
        std::cout << "=====================================" << std::endl;
        
        std::string username = "testuser_" + std::to_string(std::time(nullptr));
        std::string password = "testpass123";
        
        // Test 1: Register
        bool registerSuccess = testRegister(username, password);
        
        // Test 2: Login with ECDSA hardware key
        bool loginSuccess = false;
        if (registerSuccess) {
            loginSuccess = testLogin(username, password);
        }
        
        // Test 3: Authenticated request (first time - register ECDH accel key)
        bool authSuccess1 = false;
        if (loginSuccess) {
            authSuccess1 = testAuthenticated();
        }
        
        // Test 4: Authenticated request (second time - use existing ECDH key)
        bool authSuccess2 = false;
        if (authSuccess1) {
            std::cout << "\n=== Testing Second Authenticated Request ===" << std::endl;
            authSuccess2 = testAuthenticated();
        }
        
        // Test 5: Third authenticated request to verify ECDH key persistence
        bool authSuccess3 = false;
        if (authSuccess2) {
            std::cout << "\n=== Testing Third Authenticated Request ===" << std::endl;
            authSuccess3 = testAuthenticated();
        }
        
        // Summary
        std::cout << "\n=====================================" << std::endl;
        std::cout << "Test Results Summary:" << std::endl;
        std::cout << "=====================================" << std::endl;
        std::cout << "Registration:           " << (registerSuccess ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "Login (ECDSA HW key):   " << (loginSuccess ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "Auth (new ECDH key):    " << (authSuccess1 ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "Auth (existing ECDH):   " << (authSuccess2 ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "Auth (ECDH persistent): " << (authSuccess3 ? "✓ PASS" : "✗ FAIL") << std::endl;
        
        bool allPassed = registerSuccess && loginSuccess && authSuccess1 && authSuccess2 && authSuccess3;
        std::cout << "\nOverall Result:         " << (allPassed ? "✓ ALL TESTS PASSED" : "✗ SOME TESTS FAILED") << std::endl;
        
        if (allPassed) {
            std::cout << "\n🎉 Congratulations! All hardware-bound authentication tests passed!" << std::endl;
            std::cout << "✓ ECDSA hardware key authentication works" << std::endl;
            std::cout << "✓ ECDH acceleration key exchange works" << std::endl;
            std::cout << "✓ Key persistence and reuse works" << std::endl;
        }
        
        std::cout << "=====================================" << std::endl;
    }
};

int main() {
    try {
        std::cout << "Starting hardware-bound authentication test..." << std::endl;
        std::cout << "Testing ECDSA hardware key with ECDH acceleration key" << std::endl;
        
        TestClient client;
        client.runFullTest();
        
        std::cout << "\nTest completed. Press Enter to exit..." << std::endl;
        std::cin.get();
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        std::cin.get();
        return 1;
    }
}
