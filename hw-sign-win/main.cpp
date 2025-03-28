#include <iostream>
#include <cpr/cpr.h>
#include <windows.h>
#include <ncrypt.h>

void generateKeyPair() {
    NCRYPT_PROV_HANDLE hProvider = 0;
    NCRYPT_KEY_HANDLE hKey = 0;

    if (NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) {
        std::cerr << "Failed to open storage provider." << std::endl;
        return;
    }

    if (NCryptCreatePersistedKey(hProvider, &hKey, NCRYPT_RSA_ALGORITHM, L"MyKey", 0, 0) != ERROR_SUCCESS) {
        std::cerr << "Failed to create key." << std::endl;
        NCryptFreeObject(hProvider);
        return;
    }

    if (NCryptFinalizeKey(hKey, 0) != ERROR_SUCCESS) {
        std::cerr << "Failed to finalize key." << std::endl;
        NCryptFreeObject(hKey);
        NCryptFreeObject(hProvider);
        return;
    }

    std::cout << "Key pair generated successfully." << std::endl;

    NCryptFreeObject(hKey);
    NCryptFreeObject(hProvider);
}

void sendRequest() {
    auto response = cpr::Post(cpr::Url{"http://localhost:8080/register"},
                              cpr::Body{"{\"publicKey\":\"example_key\"}"},
                              cpr::Header{{"Content-Type", "application/json"}});

    if (response.status_code == 200) {
        std::cout << "Request successful: " << response.text << std::endl;
    } else {
        std::cerr << "Request failed with status code: " << response.status_code << std::endl;
    }
}

int main() {
    std::cout << "Generating key pair..." << std::endl;
    generateKeyPair();

    std::cout << "Sending request to server..." << std::endl;
    sendRequest();

    return 0;
}