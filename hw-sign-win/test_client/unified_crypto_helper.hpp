#pragma once

#include "test_client/types.h"

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <ctime>
#include <format>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

class UnifiedCryptoHelper {
private:
    NCRYPT_PROV_HANDLE hProvider_ = NULL;
    NCRYPT_KEY_HANDLE hHardwareKey_ = NULL;
    EC_KEY* accelEcdhKey_ = nullptr;
    std::vector<uint8_t> sharedSecret_;
    HardwareKeyType hwKeyType_;
    std::string keyTypeString_;

public:
    UnifiedCryptoHelper(HardwareKeyType keyType = HardwareKeyType::ECDSA_P256) : hwKeyType_(keyType) {
        // Initialize OpenSSL
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();

        // Initialize NCrypt for hardware key
        SECURITY_STATUS status;

        // PCPTool uses MS_PLATFORM_CRYPTO_PROVIDER; keep both keys under same provider for key attestation
        status = NCryptOpenStorageProvider(&hProvider_, MS_PLATFORM_CRYPTO_PROVIDER, 0);
        if (FAILED(status)) {
            throw std::runtime_error("Failed to open NCrypt storage provider");
        }

        // Generate hardware key based on type
        if (hwKeyType_ == HardwareKeyType::RSA_2048_PSS) {
            generateRSAHardwareKey();
            keyTypeString_ = "rsa-2048-pss";
        }
        else {
            generateECDSAHardwareKey();
            keyTypeString_ = "ecdsa-p256";
        }

        // Generate ECDH P-256 key using OpenSSL for acceleration
        accelEcdhKey_ = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!accelEcdhKey_ || !EC_KEY_generate_key(accelEcdhKey_)) {
            throw std::runtime_error("Failed to generate ECDH acceleration key");
        }

        std::cout << "Generated " << keyTypeString_ <<
            " hardware key (NCrypt) and ECDH P-256 acceleration key (OpenSSL)" << std::endl;
    }

    ~UnifiedCryptoHelper() {
        if (hHardwareKey_) {
            NCryptDeleteKey(hHardwareKey_, 0);
            NCryptFreeObject(hHardwareKey_);
        }
        if (hProvider_) {
            NCryptFreeObject(hProvider_);
        }
        if (accelEcdhKey_) {
            EC_KEY_free(accelEcdhKey_);
        }
    }

private:
    std::wstring getHardwareKeyProperty(std::wstring name, std::string type) {
        SECURITY_STATUS status;
        DWORD cbResult = 0;
        status = NCryptGetProperty(hHardwareKey_, name.data(),
                                   NULL, cbResult, &cbResult, 0);
        if (FAILED(status)) {
            return L"N/A";
        }

        std::vector<BYTE> w;
        w.resize(cbResult);
        status = NCryptGetProperty(hHardwareKey_, name.data(),
                                   (PBYTE)w.data(), cbResult, &cbResult, 0);
        if (FAILED(status)) {
            throw std::runtime_error("Failed to get property value");
        }

        if (type == "string") {
            return (WCHAR*)w.data();
        }

        if (type == "bool") {
            return w[0] == 0 ? L"false" : L"true";
        }

        if (type == "int") {
            return std::to_wstring(*(DWORD*)w.data());
        }

        if (type == "binary") {
            std::wstring result = L"0x";
            for (BYTE byte : w) {
                result += std::format(L"{:02X}", byte);
            }
            return result;
        }

        return L"N/A";
    }

    void printHardwareKeyProperties() {
        std::pair<std::wstring, std::string> all_properties[] = {
            {NCRYPT_ALGORITHM_PROPERTY, "string"},
            {NCRYPT_LENGTH_PROPERTY, "string"},
            {NCRYPT_BLOCK_LENGTH_PROPERTY, "string"},
            {NCRYPT_ECC_CURVE_NAME_PROPERTY, "string"},
            {NCRYPT_PCP_PLATFORM_TYPE_PROPERTY, "string"},
            {NCRYPT_PCP_KEYATTESTATION_PROPERTY, "string"},
            {NCRYPT_PCP_EKPUB_PROPERTY, "string"},
            {NCRYPT_PCP_EKCERT_PROPERTY, "string"},
            {NCRYPT_PCP_EKNVCERT_PROPERTY, "string"},
            {NCRYPT_PCP_PCRTABLE_PROPERTY, "string"},
            {NCRYPT_PCP_SESSIONID_PROPERTY, "string"},
            {NCRYPT_PCP_EXPORT_ALLOWED_PROPERTY, "bool"},
            {NCRYPT_PCP_TPM_VERSION_PROPERTY, "string"},
            {NCRYPT_PCP_TPM_FW_VERSION_PROPERTY, "string"},
            {NCRYPT_PCP_TPM_MANUFACTURER_ID_PROPERTY, "string"},
            {NCRYPT_PCP_TPM2BNAME_PROPERTY, "binary"},
            {NCRYPT_PCP_PLATFORMHANDLE_PROPERTY, "binary"},
            {NCRYPT_PCP_PROVIDERHANDLE_PROPERTY, "binary"},
        };

        for (const auto& [name, type] : all_properties) {
            std::wstring value = getHardwareKeyProperty(name, type);
            std::wcout << L"Property " << name << L": " << value << std::endl;
        }
    }

    void generateECDSAHardwareKey() {
        std::wstring hwKeyName = L"HwSignTestECDSA_" + std::to_wstring(std::time(nullptr));
        SECURITY_STATUS status = NCryptCreatePersistedKey(
            hProvider_,
            &hHardwareKey_,
            BCRYPT_ECDSA_P256_ALGORITHM,
            hwKeyName.c_str(),
            0,
            NCRYPT_OVERWRITE_KEY_FLAG
        );

        if (FAILED(status)) {
            throw std::runtime_error("Failed to create ECDSA hardware key");
        }

        // Finalize the key
        status = NCryptFinalizeKey(hHardwareKey_, 0);
        if (FAILED(status)) {
            NCryptFreeObject(hHardwareKey_);
            throw std::runtime_error("Failed to finalize ECDSA hardware key");
        }

        printHardwareKeyProperties();
    }

    void generateRSAHardwareKey() {
        std::wstring hwKeyName = L"HwSignTestRSA_" + std::to_wstring(std::time(nullptr));
        SECURITY_STATUS status = NCryptCreatePersistedKey(
            hProvider_,
            &hHardwareKey_,
            BCRYPT_RSA_ALGORITHM,
            hwKeyName.c_str(),
            0,
            NCRYPT_OVERWRITE_KEY_FLAG
        );

        if (FAILED(status)) {
            throw std::runtime_error("Failed to create RSA hardware key");
        }

        // Set key length to 2048 bits
        DWORD keyLength = 2048;
        status = NCryptSetProperty(
            hHardwareKey_,
            NCRYPT_LENGTH_PROPERTY,
            (PBYTE)&keyLength,
            sizeof(keyLength),
            0
        );

        if (FAILED(status)) {
            NCryptFreeObject(hHardwareKey_);
            throw std::runtime_error("Failed to set RSA key length");
        }

        // Finalize the key
        status = NCryptFinalizeKey(hHardwareKey_, 0);
        if (FAILED(status)) {
            NCryptFreeObject(hHardwareKey_);
            throw std::runtime_error("Failed to finalize RSA hardware key");
        }
    }

public:
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

    std::string exportHardwarePublicKey() {
        DWORD cbResult = 0;
        SECURITY_STATUS status;

        // First, export the key
        status = NCryptExportKey(
            hHardwareKey_,
            NULL,
            BCRYPT_PUBLIC_KEY_BLOB,
            NULL,
            NULL,
            0,
            &cbResult,
            0
        );

        if (FAILED(status)) {
            throw std::runtime_error("Failed to get public key size");
        }

        std::vector<uint8_t> keyBlob(cbResult);
        status = NCryptExportKey(
            hHardwareKey_,
            NULL,
            BCRYPT_PUBLIC_KEY_BLOB,
            NULL,
            keyBlob.data(),
            cbResult,
            &cbResult,
            0
        );

        if (FAILED(status)) {
            throw std::runtime_error("Failed to export public key");
        }

        // Convert to standard format based on key type
        if (hwKeyType_ == HardwareKeyType::ECDSA_P256) {
            return convertECDSAKeyToPKIX(keyBlob);
        }
        else {
            return convertRSAKeyToPKIX(keyBlob);
        }
    }

private:
    std::string convertECDSAKeyToPKIX(std::vector<uint8_t>& keyBlob) {
        // BCrypt ECC public key blob structure
        BCRYPT_ECCKEY_BLOB* eccBlob = (BCRYPT_ECCKEY_BLOB*)keyBlob.data();

        // Extract X and Y coordinates
        BYTE* x = keyBlob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
        BYTE* y = x + eccBlob->cbKey;

        // Create OpenSSL EC_KEY
        EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ecKey) {
            throw std::runtime_error("Failed to create EC_KEY");
        }

        // Create EC_POINT from coordinates
        const EC_GROUP* group = EC_KEY_get0_group(ecKey);
        EC_POINT* point = EC_POINT_new(group);
        BIGNUM* bn_x = BN_bin2bn(x, eccBlob->cbKey, NULL);
        BIGNUM* bn_y = BN_bin2bn(y, eccBlob->cbKey, NULL);

        if (!EC_POINT_set_affine_coordinates_GFp(group, point, bn_x, bn_y, NULL)) {
            BN_free(bn_x);
            BN_free(bn_y);
            EC_POINT_free(point);
            EC_KEY_free(ecKey);
            throw std::runtime_error("Failed to set EC point coordinates");
        }

        EC_KEY_set_public_key(ecKey, point);

        // Convert to EVP_PKEY
        EVP_PKEY* pkey = EVP_PKEY_new();
        EVP_PKEY_set1_EC_KEY(pkey, ecKey);

        // Export to PKIX format
        BIO* bio = BIO_new(BIO_s_mem());
        i2d_PUBKEY_bio(bio, pkey);

        BUF_MEM* bufferPtr;
        BIO_get_mem_ptr(bio, &bufferPtr);
        std::vector<uint8_t> pkixKey(bufferPtr->data, bufferPtr->data + bufferPtr->length);

        // Cleanup
        BN_free(bn_x);
        BN_free(bn_y);
        EC_POINT_free(point);
        EC_KEY_free(ecKey);
        EVP_PKEY_free(pkey);
        BIO_free(bio);

        return base64Encode(pkixKey);
    }

    std::string convertRSAKeyToPKIX(std::vector<uint8_t>& keyBlob) {
        // BCrypt RSA public key blob structure
        BCRYPT_RSAKEY_BLOB* rsaBlob = (BCRYPT_RSAKEY_BLOB*)keyBlob.data();

        // Extract modulus and exponent
        BYTE* exponent = keyBlob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
        BYTE* modulus = exponent + rsaBlob->cbPublicExp;

        // Create OpenSSL RSA key
        RSA* rsaKey = RSA_new();
        BIGNUM* n = BN_bin2bn(modulus, rsaBlob->cbModulus, NULL);
        BIGNUM* e = BN_bin2bn(exponent, rsaBlob->cbPublicExp, NULL);

        if (!RSA_set0_key(rsaKey, n, e, NULL)) {
            BN_free(n);
            BN_free(e);
            RSA_free(rsaKey);
            throw std::runtime_error("Failed to set RSA key components");
        }

        // Convert to EVP_PKEY
        EVP_PKEY* pkey = EVP_PKEY_new();
        EVP_PKEY_set1_RSA(pkey, rsaKey);

        // Export to PKIX format
        BIO* bio = BIO_new(BIO_s_mem());
        i2d_PUBKEY_bio(bio, pkey);

        BUF_MEM* bufferPtr;
        BIO_get_mem_ptr(bio, &bufferPtr);
        std::vector<uint8_t> pkixKey(bufferPtr->data, bufferPtr->data + bufferPtr->length);

        // Cleanup
        RSA_free(rsaKey);
        EVP_PKEY_free(pkey);
        BIO_free(bio);

        return base64Encode(pkixKey);
    }

public:
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
        // Hash the data with SHA-256 using OpenSSL
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);

        DWORD cbSignature = 0;
        SECURITY_STATUS status;

        if (hwKeyType_ == HardwareKeyType::RSA_2048_PSS) {
            // Sign with RSA-PSS using NCrypt
            BCRYPT_PSS_PADDING_INFO paddingInfo = {0};
            paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
            paddingInfo.cbSalt = 32;

            status = NCryptSignHash(
                hHardwareKey_,
                &paddingInfo,
                hash,
                SHA256_DIGEST_LENGTH,
                NULL,
                0,
                &cbSignature,
                BCRYPT_PAD_PSS
            );

            if (FAILED(status)) {
                throw std::runtime_error("Failed to get RSA signature size");
            }

            std::vector<uint8_t> signature(cbSignature);

            status = NCryptSignHash(
                hHardwareKey_,
                &paddingInfo,
                hash,
                SHA256_DIGEST_LENGTH,
                signature.data(),
                cbSignature,
                &cbSignature,
                BCRYPT_PAD_PSS
            );

            if (FAILED(status)) {
                throw std::runtime_error("Failed to sign data with RSA hardware key");
            }

            return base64Encode(signature);
        }
        else {
            // Sign with ECDSA using NCrypt
            status = NCryptSignHash(
                hHardwareKey_,
                NULL,
                hash,
                SHA256_DIGEST_LENGTH,
                NULL,
                0,
                &cbSignature,
                0
            );

            if (FAILED(status)) {
                throw std::runtime_error("Failed to get ECDSA signature size");
            }

            std::vector<uint8_t> signature(cbSignature);

            status = NCryptSignHash(
                hHardwareKey_,
                NULL,
                hash,
                SHA256_DIGEST_LENGTH,
                signature.data(),
                cbSignature,
                &cbSignature,
                0
            );

            if (FAILED(status)) {
                throw std::runtime_error("Failed to sign data with ECDSA hardware key");
            }

            return base64Encode(signature);
        }
    }

    std::string signDataWithAccelKey(const std::string& data) {
        if (sharedSecret_.empty()) {
            // No shared secret yet, use ECDSA signing with OpenSSL
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);

            unsigned char signature[256];
            unsigned int sigLen;

            if (!ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, signature, &sigLen, accelEcdhKey_)) {
                throw std::runtime_error("Failed to sign data with acceleration key");
            }

            std::vector<uint8_t> sigVec(signature, signature + sigLen);
            return base64Encode(sigVec);
        }
        else {
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
                }
                else {
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

            std::cout << "✓ ECDH shared secret established successfully, length: " << sharedSecret_.size() << " bytes"
                << std::endl;
        }
        catch (const std::exception& e) {
            sharedSecret_.clear();
            throw std::runtime_error(std::string("ECDH key exchange failed: ") + e.what());
        }
    }

    std::string getHardwareKeyType() const {
        return keyTypeString_;
    }

    std::string getAccelKeyType() const {
        return "ecdh-p256";
    }

    // Get the hardware key handle for attestation
    NCRYPT_KEY_HANDLE getHardwareKeyHandle() const {
        return hHardwareKey_;
    }

private:
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
