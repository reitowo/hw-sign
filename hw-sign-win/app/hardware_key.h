#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>

#include <string>
#include <variant>
#include <vector>

// Hardware-backed (TPM / Platform KSP) signing key wrapper.
class HardwareKey {
public:
    HardwareKey();
    ~HardwareKey();

    HardwareKey(const HardwareKey&) = delete;
    HardwareKey& operator=(const HardwareKey&) = delete;

    std::string getKeyType() const { return keyType_; }
    std::vector<uint8_t> sign(const std::vector<uint8_t>& data);
    std::string exportPublicKey();

private:
    NCRYPT_PROV_HANDLE providerHandle_ = 0;
    NCRYPT_KEY_HANDLE keyHandle_ = 0;
    std::string keyType_;
    bool hasKey_ = false;

    std::variant<std::vector<uint8_t>, std::string> tryCreateKey(const wchar_t* algorithm);
};

