#include "app/ncrypt_utils.h"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "common/base64.h"

bool SupportsVBSBasedKeys() {
    SECURITY_STATUS status;
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    auto name = L"fun.reito.hw-sign.vbs.check";

    if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) {
        return false;
    }

    // status = NCryptOpenKey(prov, &key, name, 0, 0);
    // if (status == ERROR_SUCCESS) {
    //     std::cout << "key exist, ";
    //
    //     // First, get the NCrypt key handle properties
    //     LPCWSTR keyBlobType = BCRYPT_ECCPUBLIC_BLOB;
    //     DWORD keyBlobSize = 0;
    //     SECURITY_STATUS status;
    //
    //     // Convert BCrypt key to CryptoAPI key
    //     // For ECDSA, convert to CERT_PUBLIC_KEY_INFO using CAPI2
    //     DWORD cbPublicKeyInfo = 0;
    //     CERT_PUBLIC_KEY_INFO* pInfo = nullptr;
    //
    //     // First query the size
    //     if (!CryptExportPublicKeyInfoEx(
    //         key, 0,
    //         X509_ASN_ENCODING,
    //         nullptr,
    //         0,
    //         nullptr,
    //         nullptr,
    //         &cbPublicKeyInfo)) {
    //         DWORD dwError = GetLastError();
    //         throw std::runtime_error("Failed to export public key info size: " + std::to_string(dwError));
    //     }
    //
    //     // Allocate memory for public key info
    //     pInfo = (CERT_PUBLIC_KEY_INFO*)LocalAlloc(LPTR, cbPublicKeyInfo);
    //     if (!pInfo) {
    //         throw std::runtime_error("Memory allocation failed");
    //     }
    //
    //     // Export the public key info
    //     if (!CryptExportPublicKeyInfoEx(
    //         key, 0,
    //         X509_ASN_ENCODING,
    //         nullptr,
    //         0,
    //         nullptr,
    //         pInfo,
    //         &cbPublicKeyInfo)) {
    //         DWORD dwError = GetLastError();
    //         LocalFree(pInfo);
    //         throw std::runtime_error("Failed to export public key info: " + std::to_string(dwError));
    //     }
    //
    //     // Now encode the public key info to DER
    //     DWORD cbEncoded = 0;
    //     uint8_t* pbEncoded = nullptr;
    //     if (!CryptEncodeObjectEx(
    //         X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pInfo, CRYPT_ENCODE_ALLOC_FLAG,
    //         nullptr, &pbEncoded, &cbEncoded)) {
    //         DWORD dwError = GetLastError();
    //         LocalFree(pInfo);
    //         throw std::runtime_error("Failed to encode public key: " + std::to_string(dwError));
    //     }
    //
    //     // Allocate new buffer with correct size and copy the encoded key
    //     std::vector<uint8_t> encodedKey(cbEncoded);
    //     memcpy(encodedKey.data(), pbEncoded, cbEncoded);
    //
    //     // Clean up
    //     LocalFree(pInfo);
    //
    //     std::cout << base64Encode(encodedKey) << ", ";
    //
    //     NCryptFreeObject(key);
    //     NCryptFreeObject(prov);
    //     return true;
    // }

    status = NCryptCreatePersistedKey(
        prov,
        &key,
        BCRYPT_ECDSA_P256_ALGORITHM,
        name,
        0,
        NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_REQUIRE_VBS_FLAG
    );

    if (status != ERROR_SUCCESS) {
        NCryptFreeObject(prov);
        return false;
    }

    // Set key properties
    DWORD length = 256;
    NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&length, sizeof(length), 0);
    DWORD policy = 0;
    NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&policy, sizeof(policy), 0);

    // Generate the key
    status = NCryptFinalizeKey(key, 0);

    NCryptFreeObject(key);
    NCryptFreeObject(prov);
    return status == ERROR_SUCCESS;
}

void printAvailableAlgorithms() {
    std::cout << "Support VBS based keys: " << SupportsVBSBasedKeys() << std::endl;

    NCRYPT_PROV_HANDLE hProvider = 0;
    if (NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) {
        std::cerr << "Failed to open key storage provider" << std::endl;
        return;
    }

    DWORD dwAlgCount = 0;
    NCryptAlgorithmName* pAlgList = nullptr;
    SECURITY_STATUS status = NCryptEnumAlgorithms(
        hProvider,
        NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION | NCRYPT_SECRET_AGREEMENT_OPERATION | NCRYPT_SIGNATURE_OPERATION,
        &dwAlgCount,
        &pAlgList,
        0);

    if (status != ERROR_SUCCESS) {
        std::cerr << "Failed to enumerate algorithms: " << std::hex << status << std::endl;
        NCryptFreeObject(hProvider);
        return;
    }

    std::cout << "===== Available Cryptographic Algorithms =====" << std::endl;
    std::cout << "Found " << dwAlgCount << " algorithm(s)" << std::endl;

    for (DWORD i = 0; i < dwAlgCount; i++) {
        std::wstring algName(pAlgList[i].pszName);
        std::string name(algName.begin(), algName.end());

        std::cout << i + 1 << ". " << name << std::endl;
        std::cout << "   Class: " << pAlgList[i].dwClass << std::endl;
        std::cout << "   Operations: 0x" << std::hex << pAlgList[i].dwAlgOperations << std::dec << std::endl;
        std::cout << "   Flags: 0x" << std::hex << pAlgList[i].dwFlags << std::dec << std::endl;
        std::cout << std::endl;
    }

    // Free resources
    NCryptFreeBuffer(pAlgList);
    NCryptFreeObject(hProvider);
    std::cout << "=============================================" << std::endl;
}

