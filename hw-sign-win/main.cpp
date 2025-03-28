#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <wincrypt.h> // For CryptEncodeObjectEx and X509_ASN_ENCODING
#include <string>
#include <string_view>
#include <vector>
#include <cpr/cpr.h>
#include <iostream>
#include <format>
#include <sstream>
#include <iomanip>
#include <variant>
#include <ctime>
#include <nlohmann/json.hpp>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib") // For CryptEncodeObjectEx and related functions

// Function to enumerate and print all available algorithms
void printAvailableAlgorithms() {
    NCRYPT_PROV_HANDLE hProvider = 0;
    if (NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) {
        std::cerr << "Failed to open key storage provider" << std::endl;
        return;
    }

    DWORD dwAlgCount = 0;
    NCryptAlgorithmName *pAlgList = nullptr;
    SECURITY_STATUS status = NCryptEnumAlgorithms(
        hProvider,
        NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION | NCRYPT_SIGNATURE_OPERATION,
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

// Constants for key storage
constexpr std::wstring_view KEY_NAME = L"HW-Sign-Key";
constexpr std::wstring_view KEY_USAGE = L"Sign";

// Helper class for RAII-style NCrypt handle management
class NCryptHandleGuard {
    NCRYPT_PROV_HANDLE providerHandle_ = 0;
    NCRYPT_KEY_HANDLE keyHandle_ = 0;

public:
    NCryptHandleGuard() {
        if (NCryptOpenStorageProvider(&providerHandle_, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) {
            throw std::runtime_error("Failed to open key storage provider");
        }
    }

    ~NCryptHandleGuard() {
        if (keyHandle_) NCryptFreeObject(keyHandle_);
        if (providerHandle_) NCryptFreeObject(providerHandle_);
    }

    NCRYPT_PROV_HANDLE provider() const { return providerHandle_; }
    NCRYPT_KEY_HANDLE key() const { return keyHandle_; }
    void setKey(NCRYPT_KEY_HANDLE key) { keyHandle_ = key; }
};

// Helper function for base64 encoding
std::string base64Encode(const std::vector<uint8_t> &data) {
    static constexpr std::string_view ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result((data.size() + 2) / 3 * 4, '=');
    size_t outPos = 0;

    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t chunk = (static_cast<uint32_t>(data[i]) << 16) & 0xFF0000;
        if (i + 1 < data.size()) chunk |= (static_cast<uint32_t>(data[i + 1]) << 8) & 0xFF00;
        if (i + 2 < data.size()) chunk |= data[i + 2] & 0xFF;

        result[outPos++] = ALPHABET[(chunk >> 18) & 0x3F];
        result[outPos++] = ALPHABET[(chunk >> 12) & 0x3F];
        if (i + 1 < data.size()) result[outPos++] = ALPHABET[(chunk >> 6) & 0x3F];
        if (i + 2 < data.size()) result[outPos++] = ALPHABET[chunk & 0x3F];
    }

    return result;
}

// Helper function for base64 decoding
std::vector<uint8_t> base64Decode(std::string_view input) {
    static constexpr std::string_view ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> result;
    std::vector<int> T(256, -1);
    for (size_t i = 0; i < 64; i++) T[ALPHABET[i]] = i;

    uint32_t val = 0;
    int valb = -8;
    for (char c: input) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            result.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }

    return result;
}

// Hardware key management class
class HardwareKey {
    NCryptHandleGuard cryptGuard_;
    std::string keyType_;
    bool hasKey_ = false;

    std::variant<std::vector<uint8_t>, std::string> tryCreateKey(const wchar_t *algorithm) {
        NCRYPT_KEY_HANDLE key = 0;
        SECURITY_STATUS status;
        DWORD length = algorithm == BCRYPT_ECDSA_P256_ALGORITHM ? 256 : 2048;
        DWORD policy = NCRYPT_ALLOW_SIGNING_FLAG;

        // Try to open existing key first
        status = NCryptOpenKey(cryptGuard_.provider(), &key, KEY_NAME.data(), 0, 0);
        if (status == ERROR_SUCCESS) {
            cryptGuard_.setKey(key);
            return std::string(algorithm == BCRYPT_ECDSA_P256_ALGORITHM ? "ecdsa" : "rsa-pss");
        }

        // Create new key if it doesn't exist
        status = NCryptCreatePersistedKey(
            cryptGuard_.provider(),
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
        NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (PBYTE) &length, sizeof(length), 0);
        NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE) &policy, sizeof(policy), 0);

        // Generate the key
        status = NCryptFinalizeKey(key, 0);
        if (status != ERROR_SUCCESS) {
            NCryptFreeObject(key);
            return std::vector<uint8_t>();
        }

        cryptGuard_.setKey(key);
        return std::string(algorithm == BCRYPT_ECDSA_P256_ALGORITHM ? "ecdsa" : "rsa-pss");
    }

public:
    HardwareKey() {
        // Try algorithms in priority order
        const wchar_t *algorithms[] = {
            BCRYPT_ECDSA_P256_ALGORITHM,
            BCRYPT_RSA_ALGORITHM
        };

        for (const auto &algo: algorithms) {
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

    std::string getKeyType() const { return keyType_; }

    std::vector<uint8_t> sign(const std::vector<uint8_t> &data) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        std::vector<uint8_t> hash;
        DWORD hashSize = 0;
        DWORD resultSize = 0;

        // Calculate SHA-256 hash
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != ERROR_SUCCESS) {
            throw std::runtime_error("Failed to open hash algorithm");
        }

        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE) &hashSize, sizeof(DWORD), &resultSize, 0);
        hash.resize(hashSize);

        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != ERROR_SUCCESS) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            throw std::runtime_error("Failed to create hash");
        }

        if (BCryptHashData(hHash, (PBYTE) data.data(), data.size(), 0) != ERROR_SUCCESS) {
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
            cryptGuard_.key(),
            nullptr,
            hash.data(),
            hash.size(),
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
            cryptGuard_.key(),
            nullptr,
            hash.data(),
            hash.size(),
            signature.data(),
            signatureSize,
            &signatureSize,
            0
        );

        if (status != ERROR_SUCCESS) {
            throw std::runtime_error("Failed to sign hash");
        }

        return signature;
    }

    std::string exportPublicKey() {
        try {
            // First, get the NCrypt key handle properties
            LPCWSTR keyBlobType;
            DWORD keyBlobSize = 0;
            SECURITY_STATUS status;

            // Determine the blob type based on key type
            if (keyType_ == "ecdsa") {
                keyBlobType = BCRYPT_ECCPUBLIC_BLOB;
            } else if (keyType_ == "rsa-pss") {
                keyBlobType = BCRYPT_RSAPUBLIC_BLOB;
            } else {
                throw std::runtime_error("Unsupported key type for export");
            }

            // Convert BCrypt key to CryptoAPI key
            // For ECDSA, convert to CERT_PUBLIC_KEY_INFO using CAPI2
            DWORD cbPublicKeyInfo = 0;
            CERT_PUBLIC_KEY_INFO *pInfo = nullptr;

            // First query the size
            if (!CryptExportPublicKeyInfoEx(
                cryptGuard_.key(), 0,
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
            pInfo = (CERT_PUBLIC_KEY_INFO *) LocalAlloc(LPTR, cbPublicKeyInfo);
            if (!pInfo) {
                throw std::runtime_error("Memory allocation failed");
            }

            // Export the public key info
            if (!CryptExportPublicKeyInfoEx(
                cryptGuard_.key(), 0,
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
            uint8_t *pbEncoded = nullptr;
            if (!CryptEncodeObjectEx(
                X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pInfo, CRYPT_ENCODE_ALLOC_FLAG,
                nullptr, &pbEncoded, &cbEncoded)) {
                DWORD dwError = GetLastError();
                LocalFree(pInfo);
                throw std::runtime_error("Failed to encode public key: " + std::to_string(dwError));
            }

            // Allocate new buffer with correct size and copy the encoded key
            std::vector<uint8_t> encodedKey(cbEncoded);
            memcpy(encodedKey.data(), pbEncoded, cbEncoded);

            // Clean up
            LocalFree(pInfo);

            // Return base64 encoded key
            return base64Encode(encodedKey);
        } catch (const std::exception &e) {
            throw std::runtime_error(std::string("Failed to export public key: ") + e.what());
        }
    }
};

// Authentication service class
class AuthService {
    HardwareKey hardwareKey_;
    std::string authToken_;
    std::string accelerationKeyId_;
    std::string baseUrl_ = "https://dbcs-api.ovo.fan";
    cpr::Session session_;

public:
    AuthService() : session_() {
        session_.SetUrl(baseUrl_);
        session_.SetHeader({{"Content-Type", "application/json"}});
    }

    bool register_(const std::string &username, const std::string &password) {
        try {
            // Prepare registration request
            nlohmann::json payload = {
                {"username", username},
                {"password", password}
            };

            session_.SetBody(payload.dump());
            session_.SetUrl(baseUrl_ + "/register");
            auto response = session_.Post();

            if (response.status_code == 201) {
                return true;
            }

            // Handle errors
            switch (response.status_code) {
                case 400:
                    if (!response.text.empty()) {
                        auto errorJson = nlohmann::json::parse(response.text);
                        if (errorJson.contains("message")) {
                            throw std::runtime_error(errorJson["message"].get<std::string>());
                        }
                    }
                    throw std::runtime_error("Invalid registration data");
                case 409:
                    throw std::runtime_error("Username already exists");
                default:
                    throw std::runtime_error("Server error: " + std::to_string(response.status_code));
            }
        } catch (const nlohmann::json::exception &e) {
            throw std::runtime_error("Failed to parse server response: " + std::string(e.what()));
        } catch (const std::exception &e) {
            throw;
        }
        return false;
    }

    bool login(const std::string &username, const std::string &password) {
        try {
            // Prepare login request
            nlohmann::json payload = {
                {"username", username},
                {"password", password}
            };

            // Add hardware key headers
            session_.SetHeader({
                {"x-rpc-sec-dbcs-hw-pub", hardwareKey_.exportPublicKey()},
                {"x-rpc-sec-dbcs-hw-pub-type", hardwareKey_.getKeyType()}
            });

            // Set body and URL path properly
            session_.SetBody(payload.dump());
            session_.SetUrl(baseUrl_ + "/login");
            auto response = session_.Post();

            if (response.status_code == 200) {
                auto respJson = nlohmann::json::parse(response.text);
                if (respJson.contains("token")) {
                    authToken_ = respJson["token"];
                    return true;
                }
                throw std::runtime_error("Invalid server response: missing token");
            }

            // Handle specific HTTP errors
            switch (response.status_code) {
                case 401:
                    throw std::runtime_error("Invalid username or password");
                case 400:
                    if (!response.text.empty()) {
                        auto errorJson = nlohmann::json::parse(response.text);
                        if (errorJson.contains("message")) {
                            throw std::runtime_error(errorJson["message"].get<std::string>());
                        }
                    }
                    throw std::runtime_error("Invalid request format");
                case 404:
                    throw std::runtime_error("Server endpoint not found. Check server URL");
                default:
                    throw std::runtime_error("Server error: " + std::to_string(response.status_code));
            }
        } catch (const nlohmann::json::exception &e) {
            throw std::runtime_error("Failed to parse server response: " + std::string(e.what()));
        } catch (const std::exception &e) {
            throw;
        }
        return false;
    }

    bool isAuthenticated() {
        if (authToken_.empty()) return false;

        try {
            // Prepare request data
            std::string timestamp = std::to_string(std::time(nullptr));

            // Setup common headers
            cpr::Header requestHeaders;
            requestHeaders["Authorization"] = "Bearer " + authToken_;
            requestHeaders["x-rpc-sec-dbcs-data"] = timestamp;

            // Setup request signature and headers based on acceleration key state
            if (!accelerationKeyId_.empty()) {
                // Use existing acceleration key
                requestHeaders["x-rpc-sec-dbcs-data-sig"] = base64Encode(hardwareKey_.sign({
                    timestamp.begin(), timestamp.end()
                }));
                requestHeaders["x-rpc-sec-dbcs-accel-pub-id"] = accelerationKeyId_;
            } else {
                // Generate new acceleration key and sign with hardware key
                std::string accelPub = hardwareKey_.exportPublicKey();
                std::string accelPubSig = base64Encode(hardwareKey_.sign({accelPub.begin(), accelPub.end()}));

                requestHeaders["x-rpc-sec-dbcs-accel-pub"] = accelPub;
                requestHeaders["x-rpc-sec-dbcs-accel-pub-type"] = hardwareKey_.getKeyType();
                requestHeaders["x-rpc-sec-dbcs-accel-pub-sig"] = accelPubSig;
                requestHeaders["x-rpc-sec-dbcs-data-sig"] = base64Encode(hardwareKey_.sign({
                    timestamp.begin(), timestamp.end()
                }));
            }

            session_.SetHeader(requestHeaders);

            // Use explicit path in the GET request
            session_.SetUrl(baseUrl_ + "/authenticated");
            auto response = session_.Get();

            if (response.status_code == 200) {
                // Save acceleration key ID if this was a new key registration
                auto it = response.header.find("x-rpc-sec-dbcs-accel-pub-id");
                if (it != response.header.end()) {
                    accelerationKeyId_ = it->second;
                }
                return true;
            }
        } catch (const std::exception &e) {
            std::cerr << "Authentication check failed: " << e.what() << std::endl;
        }
        return false;
    }

    void logout() {
        authToken_.clear();
        accelerationKeyId_.clear();
    }
};

// GUI Window class
class MainWindow {
    HWND windowHandle_ = nullptr;
    HWND usernameEditHandle_ = nullptr;
    HWND passwordEditHandle_ = nullptr;
    HWND loginButtonHandle_ = nullptr;
    HWND registerButtonHandle_ = nullptr;
    HWND logoutButtonHandle_ = nullptr;
    HWND checkAuthButtonHandle_ = nullptr;
    AuthService authService_;
    HBRUSH backgroundBrush_ = nullptr;
    static constexpr COLORREF BACKGROUND_COLOR = RGB(240, 240, 240);

    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        MainWindow *self = nullptr;
        if (uMsg == WM_NCCREATE) {
            CREATESTRUCT *create = reinterpret_cast<CREATESTRUCT *>(lParam);
            self = reinterpret_cast<MainWindow *>(create->lpCreateParams);
            SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        } else {
            self = reinterpret_cast<MainWindow *>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
        }

        if (self) return self->handleMessage(hwnd, uMsg, wParam, lParam);
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }

    LRESULT handleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        switch (uMsg) {
            case WM_CREATE:
                backgroundBrush_ = CreateSolidBrush(BACKGROUND_COLOR);
                createControls(hwnd);
                return 0;

            case WM_CTLCOLORSTATIC:
            case WM_CTLCOLORBTN:
            case WM_CTLCOLOREDIT:
                // Set the background color for all controls to match window
                SetBkColor((HDC) wParam, BACKGROUND_COLOR);
                return (LRESULT) backgroundBrush_;

            case WM_COMMAND:
                switch (LOWORD(wParam)) {
                    case 1: // Login button
                        onLogin();
                        return 0;
                    case 2: // Register button
                        onRegister();
                        return 0;
                    case 3: // Logout button
                        onLogout();
                        return 0;
                    case 4: // Check Auth button
                        onCheckAuth();
                        return 0;
                }
                break;

            case WM_DESTROY:
                DeleteObject(backgroundBrush_);
                PostQuitMessage(0);
                return 0;
        }
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }

    void createControls(HWND hwnd) {
        // Create fonts with Chinese support (微软雅黑)
        HFONT hFont = CreateFontW(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑");

        // Create a smaller font for labels
        HFONT hLabelFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                       CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑");

        // Center the controls in the window
        RECT clientRect;
        GetClientRect(hwnd, &clientRect);
        int centerX = (clientRect.right - clientRect.left - 320) / 2;
        int startY = 30;

        // Create title with larger font
        HFONT hTitleFont = CreateFontW(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                       CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑");

        HWND titleLabel = CreateWindowEx(0, "STATIC", "Hardware-Bound Authentication",
                                         WS_CHILD | WS_VISIBLE | SS_CENTER,
                                         centerX - 30, startY, 380, 30,
                                         hwnd, nullptr, nullptr, nullptr);
        SendMessage(titleLabel, WM_SETFONT, (WPARAM) hTitleFont, TRUE);

        // Add subtitle with explanation
        HWND subtitleLabel = CreateWindowEx(0, "STATIC", "Login with hardware-protected security token",
                                            WS_CHILD | WS_VISIBLE | SS_CENTER,
                                            centerX, startY + 35, 320, 20,
                                            hwnd, nullptr, nullptr, nullptr);
        SendMessage(subtitleLabel, WM_SETFONT, (WPARAM) hLabelFont, TRUE);

        // Create username field with better spacing
        HWND usernameLabel = CreateWindowEx(0, "STATIC", "Username:",
                                            WS_CHILD | WS_VISIBLE | SS_LEFT,
                                            centerX, startY + 75, 80, 20,
                                            hwnd, nullptr, nullptr, nullptr);
        SendMessage(usernameLabel, WM_SETFONT, (WPARAM) hLabelFont, TRUE);

        usernameEditHandle_ = CreateWindowEx(0, "EDIT", "",
                                             WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                             centerX + 90, startY + 75, 230, 26,
                                             hwnd, nullptr, nullptr, nullptr);
        SendMessage(usernameEditHandle_, WM_SETFONT, (WPARAM) hFont, TRUE);

        // Create password field
        HWND passwordLabel = CreateWindowEx(0, "STATIC", "Password:",
                                            WS_CHILD | WS_VISIBLE | SS_LEFT,
                                            centerX, startY + 110, 80, 20,
                                            hwnd, nullptr, nullptr, nullptr);
        SendMessage(passwordLabel, WM_SETFONT, (WPARAM) hLabelFont, TRUE);

        passwordEditHandle_ = CreateWindowEx(0, "EDIT", "",
                                             WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL,
                                             centerX + 90, startY + 110, 230, 26,
                                             hwnd, nullptr, nullptr, nullptr);
        SendMessage(passwordEditHandle_, WM_SETFONT, (WPARAM) hFont, TRUE);

        // Create buttons with modern style
        DWORD buttonStyle = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON;
        int buttonWidth = 85;
        int buttonHeight = 32;
        int buttonSpacing = 5;
        int buttonsStartY = startY + 155;

        // Position buttons with better spacing
        loginButtonHandle_ = CreateWindowEx(0, "BUTTON", "Login",
                                            buttonStyle,
                                            centerX, buttonsStartY, buttonWidth, buttonHeight,
                                            hwnd, (HMENU) 1, nullptr, nullptr);
        SendMessage(loginButtonHandle_, WM_SETFONT, (WPARAM) hFont, TRUE);

        registerButtonHandle_ = CreateWindowEx(0, "BUTTON", "Register",
                                               buttonStyle,
                                               centerX + buttonWidth + buttonSpacing, buttonsStartY, buttonWidth,
                                               buttonHeight,
                                               hwnd, (HMENU) 2, nullptr, nullptr);
        SendMessage(registerButtonHandle_, WM_SETFONT, (WPARAM) hFont, TRUE);

        logoutButtonHandle_ = CreateWindowEx(0, "BUTTON", "Logout",
                                             buttonStyle,
                                             centerX + (buttonWidth + buttonSpacing) * 2, buttonsStartY, buttonWidth,
                                             buttonHeight,
                                             hwnd, (HMENU) 3, nullptr, nullptr);
        SendMessage(logoutButtonHandle_, WM_SETFONT, (WPARAM) hFont, TRUE);

        checkAuthButtonHandle_ = CreateWindowEx(0, "BUTTON", "Check",
                                                buttonStyle,
                                                centerX + (buttonWidth + buttonSpacing) * 3, buttonsStartY, buttonWidth,
                                                buttonHeight,
                                                hwnd, (HMENU) 4, nullptr, nullptr);
        SendMessage(checkAuthButtonHandle_, WM_SETFONT, (WPARAM) hFont, TRUE);

        // Create status bar
        HWND statusBar = CreateWindowEx(0, "STATIC", "Ready",
                                        WS_CHILD | WS_VISIBLE | SS_CENTER,
                                        centerX, buttonsStartY + 50, 320, 20,
                                        hwnd, nullptr, nullptr, nullptr);
        SendMessage(statusBar, WM_SETFONT, (WPARAM) hLabelFont, TRUE);

        // Initially disable logout and check auth buttons
        EnableWindow(logoutButtonHandle_, FALSE);
        EnableWindow(checkAuthButtonHandle_, FALSE);
    }

    void onLogin() {
        char username[256], password[256];
        GetWindowText(usernameEditHandle_, username, 256);
        GetWindowText(passwordEditHandle_, password, 256);

        if (strlen(username) == 0 || strlen(password) == 0) {
            MessageBox(windowHandle_, "Please enter both username and password.", "Error", MB_OK | MB_ICONWARNING);
            return;
        }

        // Show loading cursor
        HCURSOR hOldCursor = SetCursor(LoadCursor(nullptr, IDC_WAIT));

        try {
            if (authService_.login(username, password)) {
                MessageBox(windowHandle_,
                           "Login successful! Your session is now protected by hardware-bound authentication.",
                           "Success", MB_OK | MB_ICONINFORMATION);
                // Enable/disable appropriate buttons
                EnableWindow(loginButtonHandle_, FALSE);
                EnableWindow(logoutButtonHandle_, TRUE);
                EnableWindow(checkAuthButtonHandle_, TRUE);
            }
        } catch (const std::exception &e) {
            MessageBox(windowHandle_, e.what(), "Login Failed", MB_OK | MB_ICONERROR);
        }

        // Restore cursor
        SetCursor(hOldCursor);
    }

    void onRegister() {
        char username[256], password[256];
        GetWindowText(usernameEditHandle_, username, 256);
        GetWindowText(passwordEditHandle_, password, 256);

        if (strlen(username) == 0 || strlen(password) == 0) {
            MessageBox(windowHandle_, "Please enter both username and password.", "Error", MB_OK | MB_ICONWARNING);
            return;
        }

        // Show loading cursor
        HCURSOR hOldCursor = SetCursor(LoadCursor(nullptr, IDC_WAIT));

        try {
            if (authService_.register_(username, password)) {
                MessageBox(windowHandle_, "Registration successful! You can now log in.", "Success",
                           MB_OK | MB_ICONINFORMATION);
            }
        } catch (const std::exception &e) {
            MessageBox(windowHandle_, e.what(), "Registration Failed", MB_OK | MB_ICONERROR);
        }

        // Restore cursor
        SetCursor(hOldCursor);
    }

    void onLogout() {
        authService_.logout();
        MessageBox(windowHandle_, "Logged out successfully!", "Success", MB_OK | MB_ICONINFORMATION);
        EnableWindow(loginButtonHandle_, TRUE);
        EnableWindow(logoutButtonHandle_, FALSE);
        EnableWindow(checkAuthButtonHandle_, FALSE);
    }

    void onCheckAuth() {
        if (authService_.isAuthenticated()) {
            MessageBox(windowHandle_, "Authentication valid and hardware-bound!", "Success",
                       MB_OK | MB_ICONINFORMATION);
        } else {
            MessageBox(windowHandle_, "Not authenticated!", "Error", MB_OK | MB_ICONERROR);
        }
    }

public:
    MainWindow() : windowHandle_(nullptr), backgroundBrush_(nullptr) {
    }

    ~MainWindow() {
        if (backgroundBrush_) DeleteObject(backgroundBrush_);
    }

    bool create() {
        WNDCLASSEX wc = {};
        wc.cbSize = sizeof(WNDCLASSEX);
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = GetModuleHandle(nullptr);
        wc.lpszClassName = "HWSignMainWindow";
        wc.hbrBackground = CreateSolidBrush(BACKGROUND_COLOR);
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
        wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

        if (!RegisterClassEx(&wc)) return false;

        // Create a larger window with centered position
        int windowWidth = 550;
        int windowHeight = 320;
        int screenWidth = GetSystemMetrics(SM_CXSCREEN);
        int screenHeight = GetSystemMetrics(SM_CYSCREEN);
        int windowX = (screenWidth - windowWidth) / 2;
        int windowY = (screenHeight - windowHeight) / 2;

        windowHandle_ = CreateWindowEx(
            WS_EX_CLIENTEDGE,
            "HWSignMainWindow",
            "Hardware-Bound Authentication System",
            WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX),
            windowX, windowY,
            windowWidth, windowHeight,
            nullptr,
            nullptr,
            GetModuleHandle(nullptr),
            this
        );

        return windowHandle_ != nullptr;
    }

    void show(int nCmdShow) {
        ShowWindow(windowHandle_, nCmdShow);
    }

    HWND handle() const { return windowHandle_; }
};

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    try {
        // Print available algorithms at startup
        printAvailableAlgorithms();

        MainWindow mainWindow;
        if (!mainWindow.create()) {
            MessageBox(nullptr, "Failed to create window", "Error", MB_OK | MB_ICONERROR);
            return 1;
        }

        mainWindow.show(nCmdShow);

        MSG msg = {};
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        return static_cast<int>(msg.wParam);
    } catch (const std::exception &e) {
        MessageBoxA(nullptr, e.what(), "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
}
