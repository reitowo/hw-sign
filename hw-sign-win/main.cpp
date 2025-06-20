#define NOMINMAX

#include <iostream>
#include <string>
#include <vector>
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <ctime>
#include <memory>
#include <sstream>
#include <iomanip>
#include <format>

#include "TpmAtt.h"

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "TpmAtt.lib")

enum class HardwareKeyType {
    ECDSA_P256,
    RSA_2048_PSS
};

class UnifiedCryptoHelper {
private:
    NCRYPT_PROV_HANDLE hProvider_ = NULL;
    NCRYPT_KEY_HANDLE hHardwareKey_ = NULL;
    NCRYPT_KEY_HANDLE hAIKKey_ = NULL;
    EC_KEY *accelEcdhKey_ = nullptr;
    std::vector<uint8_t> sharedSecret_;
    HardwareKeyType hwKeyType_;
    std::string keyTypeString_;
    std::wstring aikName_;

public:
    UnifiedCryptoHelper(HardwareKeyType keyType = HardwareKeyType::ECDSA_P256) : hwKeyType_(keyType) {
        // Initialize OpenSSL
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();

        // Initialize NCrypt for hardware key
        SECURITY_STATUS status;

        // Open the default key storage provider
        status = NCryptOpenStorageProvider(&hProvider_, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
        if (FAILED(status)) {
            throw std::runtime_error("Failed to open NCrypt storage provider");
        }

        // Generate hardware key based on type
        if (hwKeyType_ == HardwareKeyType::RSA_2048_PSS) {
            generateRSAHardwareKey();
            keyTypeString_ = "rsa-2048-pss";
        } else {
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
        if (hAIKKey_) {
            NCryptDeleteKey(hAIKKey_, 0);
            NCryptFreeObject(hAIKKey_);
        }
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
                                   (PBYTE) w.data(), cbResult, &cbResult, 0);
        if (FAILED(status)) {
            throw std::runtime_error("Failed to get property value");
        }

        if (type == "string") {
            return (WCHAR *) w.data();
        }

        if (type == "bool") {
            return w[0] == 0 ? L"false" : L"true";
        }

        if (type == "int") {
            return std::to_wstring(*(DWORD *) w.data());
        }

        if (type == "binary") {
            std::wstring result = L"0x";
            for (BYTE byte: w) {
                result += std::format(L"{:02X}", byte);
            }
            return result;
        }
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

        for (const auto &[name, type]: all_properties) {
            std::wstring value = getHardwareKeyProperty(name, type);
            std::wcout << L"Property " << name << L": " << value << std::endl;
        }
    }

    void printAIKProperties() {
        std::wcout << L"\n--- AIK Properties ---" << std::endl;

        std::pair<std::wstring, std::string> aik_properties[] = {
            {NCRYPT_ALGORITHM_PROPERTY, "string"},
            {NCRYPT_LENGTH_PROPERTY, "string"},
            {NCRYPT_KEY_USAGE_PROPERTY, "int"},
            {NCRYPT_PCP_PLATFORM_TYPE_PROPERTY, "string"},
            {NCRYPT_PCP_TPM_VERSION_PROPERTY, "string"},
        };

        for (const auto &[name, type]: aik_properties) {
            std::wstring value = getAIKProperty(name, type);
            std::wcout << L"AIK " << name << L": " << value << std::endl;
        }
        std::wcout << L"--- End AIK Properties ---\n" << std::endl;
    }

    std::wstring getAIKProperty(std::wstring name, std::string type) {
        SECURITY_STATUS status;
        DWORD cbResult = 0;
        status = NCryptGetProperty(hAIKKey_, name.data(),
                                   NULL, cbResult, &cbResult, 0);
        if (FAILED(status)) {
            return L"N/A";
        }

        std::vector<BYTE> w;
        w.resize(cbResult);
        status = NCryptGetProperty(hAIKKey_, name.data(),
                                   (PBYTE) w.data(), cbResult, &cbResult, 0);
        if (FAILED(status)) {
            return L"Error";
        }

        if (type == "string") {
            return (WCHAR *) w.data();
        }

        if (type == "bool") {
            return w[0] == 0 ? L"false" : L"true";
        }

        if (type == "int") {
            return std::to_wstring(*(DWORD *) w.data());
        }

        if (type == "binary") {
            std::wstring result = L"0x";
            for (BYTE byte: w) {
                result += std::format(L"{:02X}", byte);
            }
            return result;
        }

        return L"Unknown";
    }

    std::string getRealPCRValues() {
        std::cout << "Retrieving PCR values from TPM..." << std::endl;

        HRESULT hr = S_OK;
        NCRYPT_PROV_HANDLE hProv = NULL;
        BYTE pcrTable[TPM_AVAILABLE_PLATFORM_PCRS * MAX_DIGEST_SIZE] = {0};
        DWORD cbPcrTable = sizeof(pcrTable);
        DWORD digestSize = SHA1_DIGEST_SIZE;

        try {
            // Open the platform crypto provider
            hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                &hProv,
                MS_PLATFORM_CRYPTO_PROVIDER,
                0));

            if (FAILED(hr)) {
                throw std::runtime_error("Failed to open platform crypto provider: " + std::to_string(hr));
            }

            // Get PCR table from TPM
            hr = HRESULT_FROM_WIN32(NCryptGetProperty(hProv,
                                                      NCRYPT_PCP_PCRTABLE_PROPERTY,
                                                      pcrTable,
                                                      sizeof(pcrTable),
                                                      &cbPcrTable,
                                                      0));

            if (FAILED(hr)) {
                throw std::runtime_error("Failed to get PCR table: " + std::to_string(hr));
            }

            // Determine digest size based on returned data
            if ((cbPcrTable / TPM_AVAILABLE_PLATFORM_PCRS) == SHA256_DIGEST_SIZE) {
                digestSize = SHA256_DIGEST_SIZE;
                std::cout << "Using SHA256 PCRs (" << digestSize << " bytes per PCR)" << std::endl;
            } else {
                std::cout << "Using SHA1 PCRs (" << digestSize << " bytes per PCR)" << std::endl;
            }

            std::cout << "Retrieved " << cbPcrTable << " bytes of PCR data for " << TPM_AVAILABLE_PLATFORM_PCRS <<
                    " PCRs" << std::endl;

            // Debug: Print first few PCRs
            std::cout << "Sample PCR values:" << std::endl;
            for (UINT32 n = 0; n < std::min(4U, (UINT32)TPM_AVAILABLE_PLATFORM_PCRS); n++) {
                std::cout << "  PCR[" << n << "]: ";
                for (UINT32 m = 0; m < std::min(8Ul, digestSize); m++) {
                    std::cout << std::format("{:02x}", pcrTable[n * digestSize + m]);
                }
                std::cout << "..." << std::endl;
            }

            // Convert to base64
            std::vector<uint8_t> pcrData(pcrTable, pcrTable + cbPcrTable);
            std::string result = base64Encode(pcrData);

            // Cleanup
            if (hProv) {
                NCryptFreeObject(hProv);
            }

            return result;
        } catch (...) {
            // Cleanup on error
            if (hProv) {
                NCryptFreeObject(hProv);
            }
            throw;
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
            (PBYTE) &keyLength,
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
    struct AttestationData {
        std::string attestation;
        std::string aikPublicKey;
        std::string pcrValues;
        std::string keyType;
    };

    std::string base64Encode(const std::vector<uint8_t> &data) {
        BIO *bio = BIO_new(BIO_s_mem());
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);

        BIO_write(bio, data.data(), data.size());
        BIO_flush(bio);

        BUF_MEM *bufferPtr;
        BIO_get_mem_ptr(bio, &bufferPtr);

        std::string result(bufferPtr->data, bufferPtr->length);
        BIO_free_all(bio);

        return result;
    }

    std::vector<uint8_t> base64Decode(const std::string &input) {
        BIO *bio = BIO_new_mem_buf(input.data(), input.length());
        BIO *b64 = BIO_new(BIO_f_base64());
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
        } else {
            return convertRSAKeyToPKIX(keyBlob);
        }
    }

private:
    std::string convertECDSAKeyToPKIX(std::vector<uint8_t> &keyBlob) {
        // BCrypt ECC public key blob structure
        BCRYPT_ECCKEY_BLOB *eccBlob = (BCRYPT_ECCKEY_BLOB *) keyBlob.data();

        // Extract X and Y coordinates
        BYTE *x = keyBlob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
        BYTE *y = x + eccBlob->cbKey;

        // Create OpenSSL EC_KEY
        EC_KEY *ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ecKey) {
            throw std::runtime_error("Failed to create EC_KEY");
        }

        // Create EC_POINT from coordinates
        const EC_GROUP *group = EC_KEY_get0_group(ecKey);
        EC_POINT *point = EC_POINT_new(group);
        BIGNUM *bn_x = BN_bin2bn(x, eccBlob->cbKey, NULL);
        BIGNUM *bn_y = BN_bin2bn(y, eccBlob->cbKey, NULL);

        if (!EC_POINT_set_affine_coordinates_GFp(group, point, bn_x, bn_y, NULL)) {
            BN_free(bn_x);
            BN_free(bn_y);
            EC_POINT_free(point);
            EC_KEY_free(ecKey);
            throw std::runtime_error("Failed to set EC point coordinates");
        }

        EC_KEY_set_public_key(ecKey, point);

        // Convert to EVP_PKEY
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY_set1_EC_KEY(pkey, ecKey);

        // Export to PKIX format
        BIO *bio = BIO_new(BIO_s_mem());
        i2d_PUBKEY_bio(bio, pkey);

        BUF_MEM *bufferPtr;
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

    std::string convertRSAKeyToPKIX(std::vector<uint8_t> &keyBlob) {
        // BCrypt RSA public key blob structure
        BCRYPT_RSAKEY_BLOB *rsaBlob = (BCRYPT_RSAKEY_BLOB *) keyBlob.data();

        // Extract modulus and exponent
        BYTE *exponent = keyBlob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
        BYTE *modulus = exponent + rsaBlob->cbPublicExp;

        // Create OpenSSL RSA key
        RSA *rsaKey = RSA_new();
        BIGNUM *n = BN_bin2bn(modulus, rsaBlob->cbModulus, NULL);
        BIGNUM *e = BN_bin2bn(exponent, rsaBlob->cbPublicExp, NULL);

        if (!RSA_set0_key(rsaKey, n, e, NULL)) {
            BN_free(n);
            BN_free(e);
            RSA_free(rsaKey);
            throw std::runtime_error("Failed to set RSA key components");
        }

        // Convert to EVP_PKEY
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY_set1_RSA(pkey, rsaKey);

        // Export to PKIX format
        BIO *bio = BIO_new(BIO_s_mem());
        i2d_PUBKEY_bio(bio, pkey);

        BUF_MEM *bufferPtr;
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
        EVP_PKEY *pkey = EVP_PKEY_new();
        if (!pkey || !EVP_PKEY_set1_EC_KEY(pkey, accelEcdhKey_)) {
            throw std::runtime_error("Failed to create EVP_PKEY for accel key");
        }

        // Export to PKIX format
        BIO *bio = BIO_new(BIO_s_mem());
        if (!i2d_PUBKEY_bio(bio, pkey)) {
            BIO_free(bio);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to export acceleration public key");
        }

        BUF_MEM *bufferPtr;
        BIO_get_mem_ptr(bio, &bufferPtr);

        std::vector<uint8_t> keyData(bufferPtr->data, bufferPtr->data + bufferPtr->length);

        BIO_free(bio);
        EVP_PKEY_free(pkey);

        return base64Encode(keyData);
    }

    std::string signDataWithHardwareKey(const std::string &data) {
        // Hash the data with SHA-256 using OpenSSL
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char *>(data.c_str()), data.length(), hash);

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
        } else {
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

    std::string signDataWithAccelKey(const std::string &data) {
        if (sharedSecret_.empty()) {
            // No shared secret yet, use ECDSA signing with OpenSSL
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char *>(data.c_str()), data.length(), hash);

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

    std::string computeHMAC(const std::string &data, const std::vector<uint8_t> &key) {
        unsigned char result[EVP_MAX_MD_SIZE];
        unsigned int result_len;

        HMAC(EVP_sha256(), key.data(), key.size(),
             reinterpret_cast<const unsigned char *>(data.c_str()), data.length(),
             result, &result_len);

        std::vector<uint8_t> hmacVec(result, result + result_len);
        return base64Encode(hmacVec);
    }

    void setSharedSecret(const std::string &serverPubKeyBase64) {
        try {
            std::cout << "Setting up ECDH shared secret..." << std::endl;

            // Decode server's public key from base64
            std::vector<uint8_t> serverPubKeyBytes = base64Decode(serverPubKeyBase64);
            std::cout << "Decoded server public key, length: " << serverPubKeyBytes.size() << " bytes" << std::endl;

            // Create BIO from server's public key bytes
            BIO *bio = BIO_new_mem_buf(serverPubKeyBytes.data(), static_cast<int>(serverPubKeyBytes.size()));
            if (!bio) {
                throw std::runtime_error("Failed to create BIO from server public key");
            }

            // Try to parse as PKIX format first
            EVP_PKEY *serverPubKey = d2i_PUBKEY_bio(bio, nullptr);
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
            EVP_PKEY *clientPrivKey = EVP_PKEY_new();
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
        } catch (const std::exception &e) {
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

    AttestationData getHardwareKeyAttestation(const std::string &nonce = "") {
        std::cout << "\n=== Generating Hardware Key Attestation using TpmAtt ===" << std::endl;

        AttestationData result;
        SECURITY_STATUS status;
        HRESULT hr;

        try {
            // Step 1: Create an AIK (Attestation Identity Key)
            aikName_ = L"HwSignAIK_" + std::to_wstring(std::time(nullptr));

            status = NCryptCreatePersistedKey(
                hProvider_,
                &hAIKKey_,
                BCRYPT_RSA_ALGORITHM,
                aikName_.c_str(),
                0,
                NCRYPT_OVERWRITE_KEY_FLAG
            );

            if (FAILED(status)) {
                throw std::runtime_error("Failed to create AIK: " + std::to_string(status));
            }

            // Mark as AIK for signing and attestation
            DWORD keyUsage = NCRYPT_ALLOW_SIGNING_FLAG;
            status = NCryptSetProperty(
                hAIKKey_,
                NCRYPT_KEY_USAGE_PROPERTY,
                (PBYTE) &keyUsage,
                sizeof(keyUsage),
                0
            );

            if (FAILED(status)) {
                NCryptDeleteKey(hAIKKey_, 0);
                throw std::runtime_error("Failed to set AIK usage: " + std::to_string(status));
            }

            DWORD dwKeyUsage = NCRYPT_PCP_IDENTITY_KEY;
            if (FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                hAIKKey_,
                NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
                (PBYTE)&dwKeyUsage,
                sizeof(dwKeyUsage),
                0)))) {
                throw std::runtime_error("Failed to set AIK usage: " + std::to_string(status));
            }

            // Finalize the AIK
            status = NCryptFinalizeKey(hAIKKey_, 0);
            if (FAILED(status)) {
                NCryptDeleteKey(hAIKKey_, 0);
                throw std::runtime_error("Failed to finalize AIK: " + std::to_string(status));
            }

            std::cout << "✓ Created RSA-2048 AIK: " << std::string(aikName_.begin(), aikName_.end()) << std::endl;

            // Print AIK properties for debugging
            try {
                printAIKProperties();
            } catch (...) {
                std::cout << "Warning: Could not print AIK properties" << std::endl;
            }

            // Step 2: Export AIK public key
            DWORD cbAIKPub = 0;
            status = NCryptExportKey(
                hAIKKey_,
                NULL,
                BCRYPT_PUBLIC_KEY_BLOB,
                NULL,
                NULL,
                0,
                &cbAIKPub,
                0
            );

            if (FAILED(status)) {
                throw std::runtime_error("Failed to get AIK public key size");
            }

            std::vector<uint8_t> aikPubBlob(cbAIKPub);
            status = NCryptExportKey(
                hAIKKey_,
                NULL,
                BCRYPT_PUBLIC_KEY_BLOB,
                NULL,
                aikPubBlob.data(),
                cbAIKPub,
                &cbAIKPub,
                0
            );

            if (FAILED(status)) {
                throw std::runtime_error("Failed to export AIK public key");
            }

            // Convert to PKIX format
            result.aikPublicKey = convertRSAKeyToPKIX(aikPubBlob);
            std::cout << "✓ Exported AIK public key" << std::endl;

            // Step 3: Use TpmAttGenerateKeyAttestation to generate real TPM attestation
            std::vector<uint8_t> nonceBytes;
            PBYTE pbNonce = nullptr;
            UINT32 cbNonce = 0;

            if (!nonce.empty()) {
                nonceBytes = base64Decode(nonce);
                pbNonce = nonceBytes.data();
                cbNonce = static_cast<UINT32>(nonceBytes.size());
                std::cout << "Using nonce of size: " << cbNonce << " bytes" << std::endl;
            }

            // Verify both keys are on the same provider
            std::cout << "Verifying keys are on the same provider..." << std::endl;
            std::cout << "Hardware key handle: " << std::hex << hHardwareKey_ << std::dec << std::endl;
            std::cout << "AIK handle: " << std::hex << hAIKKey_ << std::dec << std::endl;
            std::cout << "Provider handle: " << std::hex << hProvider_ << std::dec << std::endl;

            // First call to get required buffer size
            UINT32 cbAttestation = 0;
            std::cout << "Calling TpmAttGenerateKeyAttestation to get buffer size..." << std::endl;

            hr = TpmAttGenerateKeyAttestation(
                hAIKKey_, // AIK handle
                hHardwareKey_, // Hardware key to attest
                pbNonce, // Optional nonce
                cbNonce, // Nonce size
                nullptr, // Output buffer (null to get size)
                0, // Buffer size
                &cbAttestation // Required size
            );

            std::cout << "TpmAttGenerateKeyAttestation result: 0x" << std::hex << hr << std::dec << std::endl;

            if (hr != HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) && FAILED(hr)) {
                std::string errorMsg = "Failed to get attestation buffer size: 0x" +
                                       std::to_string(hr) + " (" + std::to_string(hr) + ")";

                // Check for specific TPM error codes
                if ((hr & 0x0000FFFF) == 0x0000001D) {
                    // TPM_RC_SCHEME
                    errorMsg += " - TPM_RC_SCHEME: The signing scheme is not supported by the TPM";
                } else if ((hr & 0x0000FFFF) == 0x00000143) {
                    // TPM_RC_KEY
                    errorMsg += " - TPM_RC_KEY: Key handle references a key that is not suitable for the operation";
                } else if ((hr & 0x0000FFFF) == 0x00000184) {
                    // TPM_RC_ATTRIBUTES
                    errorMsg += " - TPM_RC_ATTRIBUTES: Key attributes are not compatible with the operation";
                }

                throw std::runtime_error(errorMsg);
            }

            std::cout << "Required attestation buffer size: " << cbAttestation << " bytes" << std::endl;

            // Second call to generate actual attestation
            std::vector<uint8_t> attestationBlob(cbAttestation);
            hr = TpmAttGenerateKeyAttestation(
                hAIKKey_, // AIK handle
                hHardwareKey_, // Hardware key to attest
                pbNonce, // Optional nonce
                cbNonce, // Nonce size
                attestationBlob.data(), // Output buffer
                cbAttestation, // Buffer size
                &cbAttestation // Actual size used
            );

            if (FAILED(hr)) {
                throw std::runtime_error("Failed to generate key attestation: " + std::to_string(hr));
            }

            // Resize to actual used size
            attestationBlob.resize(cbAttestation);

            result.attestation = base64Encode(attestationBlob);
            result.keyType = keyTypeString_;

            // Get real PCR values from TPM
            try {
                result.pcrValues = getRealPCRValues();
                std::cout << "✓ Retrieved real PCR values from TPM" << std::endl;
            } catch (const std::exception &e) {
                std::cout << "Warning: Could not get real PCR values: " << e.what() << std::endl;
                // Fallback to empty PCR values if platform access fails
                result.pcrValues = "";
            }

            std::cout << "✓ Generated TPM key attestation using TmpAtt library" << std::endl;
            std::cout << "  Attestation size: " << cbAttestation << " bytes" << std::endl;
            std::cout << "  Key type: " << result.keyType << std::endl;

            return result;
        } catch (const std::exception &e) {
            if (hAIKKey_) {
                NCryptDeleteKey(hAIKKey_, 0);
                NCryptFreeObject(hAIKKey_);
                hAIKKey_ = NULL;
            }
            throw;
        }
    }

private:
    EVP_PKEY *createEVPKeyFromRawPoint(const std::vector<uint8_t> &rawPoint) {
        if (rawPoint.size() != 65 || rawPoint[0] != 0x04) {
            return nullptr;
        }

        // Create EC_KEY for P-256 curve
        EC_KEY *ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ecKey) {
            return nullptr;
        }

        // Create point from raw coordinates
        const EC_GROUP *group = EC_KEY_get0_group(ecKey);
        EC_POINT *point = EC_POINT_new(group);
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
        EVP_PKEY *pkey = EVP_PKEY_new();
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

    std::vector<uint8_t> performECDHKeyDerivation(EVP_PKEY *clientPrivKey, EVP_PKEY *serverPubKey) {
        // Create derivation context
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(clientPrivKey, nullptr);
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
    std::unique_ptr<UnifiedCryptoHelper> crypto_;
    HardwareKeyType keyType_;

public:
    TestClient(HardwareKeyType keyType = HardwareKeyType::ECDSA_P256) : keyType_(keyType) {
        crypto_ = std::make_unique<UnifiedCryptoHelper>(keyType);
        std::cout << "Initialized test client with base URL: " << baseUrl_ << std::endl;
    }

    bool testRegister(const std::string &username, const std::string &password) {
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
        } catch (const std::exception &e) {
            std::cout << "✗ Registration error: " << e.what() << std::endl;
            return false;
        }
    }

    bool testLogin(const std::string &username, const std::string &password) {
        std::cout << "\n=== Testing Login ===" << std::endl;
        std::cout << "Username: " << username << std::endl;
        std::cout << "Password: " << password << std::endl;

        try {
            nlohmann::json payload = {
                {"username", username},
                {"password", password}
            };

            std::string hwPubKey = crypto_->exportHardwarePublicKey();
            std::string hwPubType = crypto_->getHardwareKeyType();

            std::cout << "Hardware public key (first 50 chars): " << hwPubKey.substr(0, 50) << "..." << std::endl;
            std::cout << "Hardware key type: " << hwPubType << std::endl;

            auto response = cpr::Post(
                cpr::Url{baseUrl_ + "/login"},
                cpr::Body{payload.dump()},
                cpr::Header{
                    {"Content-Type", "application/json"},
                    {"x-rpc-sec-bound-token-hw-pub", hwPubKey},
                    {"x-rpc-sec-bound-token-hw-pub-type", hwPubType}
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
        } catch (const std::exception &e) {
            std::cout << "✗ Login error: " << e.what() << std::endl;
            return false;
        }
    }

    bool testAuthenticated(bool generateAttestation = false) {
        std::cout << "\n=== Testing Authenticated Request" << (generateAttestation ? " with Attestation" : "") << " ==="
                << std::endl;

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
            std::cout << "Request data: " << timestamp << "-" << randomHex.substr(0, 16) << "..." << std::endl;

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

                std::cout << "Acceleration public key (first 50 chars): " << accelPub.substr(0, 50) << "..." <<
                        std::endl;
                std::cout << "Acceleration key type: " << accelPubType << std::endl;
                std::cout << "Accel pub signature (first 20 chars): " << accelPubSig.substr(0, 20) << "..." <<
                        std::endl;
                std::cout << "Data signature (first 20 chars): " << dataSig.substr(0, 20) << "..." << std::endl;
            } else {
                // Subsequent requests - use HMAC with shared secret
                std::cout << "Using existing acceleration key ID with HMAC: " << accelKeyId_ << std::endl;

                std::string dataSig = crypto_->signDataWithAccelKey(requestData);
                requestHeaders["x-rpc-sec-bound-token-accel-pub-id"] = accelKeyId_;
                requestHeaders["x-rpc-sec-bound-token-data-sig"] = dataSig;

                std::cout << "HMAC signature (first 20 chars): " << dataSig.substr(0, 20) << "..." << std::endl;
            }

            auto response = cpr::Get(
                cpr::Url{baseUrl_ + "/authenticated"},
                requestHeaders
            );

            std::cout << "Response status: " << response.status_code << std::endl;
            std::cout << "Response body: " << response.text << std::endl;

            // Check for acceleration key ID in response headers
            auto it = response.header.find("x-rpc-sec-bound-token-accel-pub-id");
            if (it != response.header.end()) {
                accelKeyId_ = it->second;
                std::cout << "Received acceleration key ID: " << accelKeyId_ << std::endl;
            }

            // Check for server's ECDH public key in response headers
            auto serverPubIt = response.header.find("x-rpc-sec-bound-token-accel-pub");
            if (serverPubIt != response.header.end()) {
                std::cout << "Received server ECDH public key (first 30 chars): "
                        << serverPubIt->second.substr(0, 30) << "..." << std::endl;

                // Establish shared secret for future HMAC operations
                crypto_->setSharedSecret(serverPubIt->second);
                std::cout << "Shared secret established for HMAC authentication" << std::endl;
            }

            if (response.status_code == 200) {
                std::cout << "✓ Authenticated request successful!" << std::endl;
                return true;
            } else {
                std::cout << "✗ Authenticated request failed!" << std::endl;
                return false;
            }
        } catch (const std::exception &e) {
            std::cout << "✗ Authenticated request error: " << e.what() << std::endl;
            return false;
        }
    }

    bool testAttestation() {
        std::cout << "\n=== Testing Hardware Key Attestation ===" << std::endl;

        if (authToken_.empty()) {
            std::cout << "✗ No auth token available!" << std::endl;
            return false;
        }

        try {
            // First, get a challenge nonce from the server
            auto challengeResponse = cpr::Get(
                cpr::Url{baseUrl_ + "/challenge"},
                cpr::Header{{"Authorization", "Bearer " + authToken_}}
            );

            if (challengeResponse.status_code != 200) {
                std::cout << "✗ Failed to get challenge: " << challengeResponse.status_code << std::endl;
                return false;
            }

            auto challengeJson = nlohmann::json::parse(challengeResponse.text);
            std::string nonce = challengeJson["nonce"];
            std::cout << "Received challenge nonce: " << nonce.substr(0, 20) << "..." << std::endl;

            // Generate attestation for the hardware key
            auto attestationData = crypto_->getHardwareKeyAttestation(nonce);

            // Send attestation to server
            nlohmann::json attestPayload = {
                {"attestation", attestationData.attestation},
                {"aik_public_key", attestationData.aikPublicKey},
                {"pcr_values", attestationData.pcrValues},
                {"key_type", attestationData.keyType},
                {"nonce", nonce}
            };

            auto attestResponse = cpr::Post(
                cpr::Url{baseUrl_ + "/attest"},
                cpr::Body{attestPayload.dump()},
                cpr::Header{
                    {"Content-Type", "application/json"},
                    {"Authorization", "Bearer " + authToken_}
                }
            );

            std::cout << "Attestation response status: " << attestResponse.status_code << std::endl;
            std::cout << "Attestation response body: " << attestResponse.text << std::endl;

            if (attestResponse.status_code == 200) {
                std::cout << "✓ Hardware key attestation successful!" << std::endl;
                return true;
            } else {
                std::cout << "✗ Hardware key attestation failed!" << std::endl;
                return false;
            }
        } catch (const std::exception &e) {
            std::cout << "✗ Attestation error: " << e.what() << std::endl;
            return false;
        }
    }

    void runFullTest() {
        std::string keyTypeStr = (keyType_ == HardwareKeyType::RSA_2048_PSS) ? "RSA-2048-PSS" : "ECDSA-P256";

        std::cout << "==========================================" << std::endl;
        std::cout << "Hardware-Bound Authentication Test" << std::endl;
        std::cout << keyTypeStr << " Hardware Key + ECDH-P256 Accel Key" << std::endl;
        std::cout << "Using NCrypt (Hardware) + OpenSSL (ECDH)" << std::endl;
        std::cout << "==========================================" << std::endl;

        std::string username = "testuser_" + keyTypeStr + "_" + std::to_string(std::time(nullptr));
        std::string password = "testpass123";

        // Test 1: Register
        bool registerSuccess = testRegister(username, password);

        // Test 2: Login with hardware key
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

        // Test 6: Hardware key attestation
        bool attestSuccess = false;
        if (authSuccess3) {
            attestSuccess = testAttestation();
        }

        // Summary
        std::cout << "\n==========================================" << std::endl;
        std::cout << "Test Results Summary:" << std::endl;
        std::cout << "==========================================" << std::endl;
        std::cout << "Registration:            " << (registerSuccess ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "Login (" << keyTypeStr << " HW):  " << (loginSuccess ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "Auth (new ECDH key):     " << (authSuccess1 ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "Auth (existing ECDH):    " << (authSuccess2 ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "Auth (ECDH persistent):  " << (authSuccess3 ? "✓ PASS" : "✗ FAIL") << std::endl;
        std::cout << "HW Key Attestation:      " << (attestSuccess ? "✓ PASS" : "✗ FAIL") << std::endl;

        bool allPassed = registerSuccess && loginSuccess && authSuccess1 && authSuccess2 && authSuccess3 &&
                         attestSuccess;
        std::cout << "\nOverall Result:          " << (allPassed ? "✓ ALL TESTS PASSED" : "✗ SOME TESTS FAILED") <<
                std::endl;

        if (allPassed) {
            std::cout << "\n🎉 Congratulations! All hardware-bound authentication tests passed!" << std::endl;
            std::cout << "✓ " << keyTypeStr << " hardware key authentication works (NCrypt)" << std::endl;
            std::cout << "✓ ECDH-P256 acceleration key exchange works (OpenSSL)" << std::endl;
            std::cout << "✓ Key persistence and reuse works" << std::endl;
            std::cout << "✓ Hardware key attestation with AIK works" << std::endl;
            std::cout << "✓ Hybrid NCrypt/OpenSSL integration successful" << std::endl;
        }

        std::cout << "==========================================" << std::endl;
    }
};

int main(int argc, char *argv[]) {
    try {
        std::cout << "Starting hardware-bound authentication test..." << std::endl;

        // Default to testing both key types
        bool testECDSA = true;
        bool testRSA = true;

        // Parse command line arguments
        if (argc > 1) {
            std::string arg = argv[1];
            if (arg == "ecdsa") {
                testRSA = false;
            } else if (arg == "rsa") {
                testECDSA = false;
            } else if (arg == "both") {
                // Test both (default)
            } else {
                std::cout << "Usage: " << argv[0] << " [ecdsa|rsa|both]" << std::endl;
                return 1;
            }
        }

        // Run tests based on selection
        if (testECDSA) {
            std::cout << "\nTesting with ECDSA-P256 hardware key..." << std::endl;
            TestClient clientECDSA(HardwareKeyType::ECDSA_P256);
            clientECDSA.runFullTest();
        }

        if (testRSA) {
            if (testECDSA) {
                std::cout << "\n\n";
            }
            std::cout << "Testing with RSA-2048-PSS hardware key..." << std::endl;
            TestClient clientRSA(HardwareKeyType::RSA_2048_PSS);
            clientRSA.runFullTest();
        }

        std::cout << "\nAll tests completed." << std::endl;
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}
