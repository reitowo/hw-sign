#include "app/hardware_key.h"

#include "common/base64.h"

#include <cstring>
#include <stdexcept>

// Constants for key storage
static constexpr std::wstring_view KEY_NAME = L"HW-Sign-Key";
static constexpr std::wstring_view KEY_USAGE = L"Sign";

std::variant<std::vector<uint8_t>, std::string> HardwareKey::tryCreateKey(const wchar_t* algorithm) {
    NCRYPT_KEY_HANDLE key = 0;
    SECURITY_STATUS status;
    DWORD length = algorithm == BCRYPT_ECDSA_P256_ALGORITHM ? 256 : 2048;
    DWORD policy = NCRYPT_ALLOW_SIGNING_FLAG;

    // Try to open existing key first
    status = NCryptOpenKey(providerHandle_, &key, KEY_NAME.data(), 0, 0);
    if (status == ERROR_SUCCESS) {
        keyHandle_ = key;
        return std::string(algorithm == BCRYPT_ECDSA_P256_ALGORITHM ? "ecdsa" : "rsa-pss");
    }

    // Create new key if it doesn't exist
    status = NCryptCreatePersistedKey(
        providerHandle_,
        &key,
        algorithm,
        KEY_NAME.data(),
        0,
        NCRYPT_OVERWRITE_KEY_FLAG
    );

    if (status != ERROR_SUCCESS) {
        return std::vector<uint8_t>();
    }

    // Set key properties
    NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&length, sizeof(length), 0);
    NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&policy, sizeof(policy), 0);

    // Generate the key
    status = NCryptFinalizeKey(key, 0);
    if (status != ERROR_SUCCESS) {
        NCryptFreeObject(key);
        return std::vector<uint8_t>();
    }

    keyHandle_ = key;
    return std::string(algorithm == BCRYPT_ECDSA_P256_ALGORITHM ? "ecdsa" : "rsa-pss");
}

HardwareKey::HardwareKey() {
    if (NCryptOpenStorageProvider(&providerHandle_, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) {
        throw std::runtime_error("Failed to open key storage provider");
    }

    // Try algorithms in priority order
    const wchar_t* algorithms[] = {
        BCRYPT_ECDSA_P256_ALGORITHM,
        BCRYPT_RSA_ALGORITHM
    };

    for (const auto& algo : algorithms) {
        auto result = tryCreateKey(algo);
        if (std::holds_alternative<std::string>(result)) {
            keyType_ = std::get<std::string>(result);
            hasKey_ = true;
            break;
        }
    }

    if (!hasKey_) {
        throw std::runtime_error("Failed to create hardware key with any algorithm");
    }
}

HardwareKey::~HardwareKey() {
    if (keyHandle_) NCryptFreeObject(keyHandle_);
    if (providerHandle_) NCryptFreeObject(providerHandle_);
}

std::vector<uint8_t> HardwareKey::sign(const std::vector<uint8_t>& data) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::vector<uint8_t> hash;
    DWORD hashSize = 0;
    DWORD resultSize = 0;

    // Calculate SHA-256 hash
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != ERROR_SUCCESS) {
        throw std::runtime_error("Failed to open hash algorithm");
    }

    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&hashSize, sizeof(DWORD), &resultSize, 0);
    hash.resize(hashSize);

    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != ERROR_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to create hash");
    }

    if (BCryptHashData(hHash, (PBYTE)data.data(), static_cast<ULONG>(data.size()), 0) != ERROR_SUCCESS) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to hash data");
    }

    if (BCryptFinishHash(hHash, hash.data(), hashSize, 0) != ERROR_SUCCESS) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to finish hash");
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // Sign the hash
    DWORD signatureSize = 0;
    SECURITY_STATUS status = NCryptSignHash(
        keyHandle_,
        nullptr,
        hash.data(),
        hashSize,
        nullptr,
        0,
        &signatureSize,
        0
    );

    if (status != ERROR_SUCCESS) {
        throw std::runtime_error("Failed to get signature size");
    }

    std::vector<uint8_t> signature(signatureSize);
    status = NCryptSignHash(
        keyHandle_,
        nullptr,
        hash.data(),
        hashSize,
        signature.data(),
        signatureSize,
        &signatureSize,
        0
    );

    if (status != ERROR_SUCCESS) {
        throw std::runtime_error("Failed to sign hash");
    }

    signature.resize(signatureSize);
    return signature;
}

std::string HardwareKey::exportPublicKey() {
    try {
        // Convert key to CERT_PUBLIC_KEY_INFO using CAPI2
        DWORD cbPublicKeyInfo = 0;
        CERT_PUBLIC_KEY_INFO* pInfo = nullptr;

        // First query the size
        if (!CryptExportPublicKeyInfoEx(
                keyHandle_,
                0,
                X509_ASN_ENCODING,
                nullptr,
                0,
                nullptr,
                nullptr,
                &cbPublicKeyInfo)) {
            DWORD dwError = GetLastError();
            throw std::runtime_error("Failed to export public key info size: " + std::to_string(dwError));
        }

        // Allocate memory for public key info
        pInfo = (CERT_PUBLIC_KEY_INFO*)LocalAlloc(LPTR, cbPublicKeyInfo);
        if (!pInfo) {
            throw std::runtime_error("Memory allocation failed");
        }

        // Export the public key info
        if (!CryptExportPublicKeyInfoEx(
                keyHandle_,
                0,
                X509_ASN_ENCODING,
                nullptr,
                0,
                nullptr,
                pInfo,
                &cbPublicKeyInfo)) {
            DWORD dwError = GetLastError();
            LocalFree(pInfo);
            throw std::runtime_error("Failed to export public key info: " + std::to_string(dwError));
        }

        // Now encode the public key info to DER
        DWORD cbEncoded = 0;
        BYTE* pbEncoded = nullptr;
        if (!CryptEncodeObjectEx(
                X509_ASN_ENCODING,
                X509_PUBLIC_KEY_INFO,
                pInfo,
                CRYPT_ENCODE_ALLOC_FLAG,
                nullptr,
                &pbEncoded,
                &cbEncoded)) {
            DWORD dwError = GetLastError();
            LocalFree(pInfo);
            throw std::runtime_error("Failed to encode public key: " + std::to_string(dwError));
        }

        // Copy encoded key
        std::vector<uint8_t> encodedKey(cbEncoded);
        std::memcpy(encodedKey.data(), pbEncoded, cbEncoded);

        // Clean up
        LocalFree(pInfo);
        LocalFree(pbEncoded);

        // Return base64 encoded key
        return base64Encode(encodedKey);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("Failed to export public key: ") + e.what());
    }
}

