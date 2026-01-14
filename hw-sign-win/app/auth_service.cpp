#include "app/auth_service.h"

#include "common/base64.h"

#include <ctime>
#include <iostream>
#include <stdexcept>

AuthService::AuthService() : session_() {
    session_.SetUrl(baseUrl_);
    session_.SetHeader({{"Content-Type", "application/json"}});
}

bool AuthService::register_(const std::string& username, const std::string& password) {
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
    }
    catch (const nlohmann::json::exception& e) {
        throw std::runtime_error("Failed to parse server response: " + std::string(e.what()));
    }
    catch (const std::exception&) {
        throw;
    }
}

bool AuthService::login(const std::string& username, const std::string& password) {
    try {
        // Prepare login request
        nlohmann::json payload = {
            {"username", username},
            {"password", password}
        };

        // Add hardware key headers
        session_.SetHeader({
            {"x-rpc-sec-bound-token-hw-pub", hardwareKey_.exportPublicKey()},
            {"x-rpc-sec-bound-token-hw-pub-type", hardwareKey_.getKeyType()}
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
    }
    catch (const nlohmann::json::exception& e) {
        throw std::runtime_error("Failed to parse server response: " + std::string(e.what()));
    }
    catch (const std::exception&) {
        throw;
    }
}

bool AuthService::isAuthenticated() {
    if (authToken_.empty()) return false;

    try {
        // Prepare request data
        std::string timestamp = std::to_string(std::time(nullptr));

        // Setup common headers
        cpr::Header requestHeaders;
        requestHeaders["Authorization"] = "Bearer " + authToken_;
        requestHeaders["x-rpc-sec-bound-token-data"] = timestamp;

        // Setup request signature and headers based on acceleration key state
        if (!accelerationKeyId_.empty()) {
            // Use existing acceleration key
            requestHeaders["x-rpc-sec-bound-token-data-sig"] = base64Encode(hardwareKey_.sign({
                timestamp.begin(), timestamp.end()
            }));
            requestHeaders["x-rpc-sec-bound-token-accel-pub-id"] = accelerationKeyId_;
        } else {
            // Generate new acceleration key and sign with hardware key
            std::string accelPub = hardwareKey_.exportPublicKey();
            std::string accelPubSig = base64Encode(hardwareKey_.sign({accelPub.begin(), accelPub.end()}));

            requestHeaders["x-rpc-sec-bound-token-accel-pub"] = accelPub;
            requestHeaders["x-rpc-sec-bound-token-accel-pub-type"] = hardwareKey_.getKeyType();
            requestHeaders["x-rpc-sec-bound-token-accel-pub-sig"] = accelPubSig;
            requestHeaders["x-rpc-sec-bound-token-data-sig"] = base64Encode(hardwareKey_.sign({
                timestamp.begin(), timestamp.end()
            }));
        }

        session_.SetHeader(requestHeaders);

        // Use explicit path in the GET request
        session_.SetUrl(baseUrl_ + "/authenticated");
        auto response = session_.Get();

        if (response.status_code == 200) {
            // Save acceleration key ID if this was a new key registration
            auto it = response.header.find("x-rpc-sec-bound-token-accel-pub-id");
            if (it != response.header.end()) {
                accelerationKeyId_ = it->second;
            }
            return true;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Authentication check failed: " << e.what() << std::endl;
    }
    return false;
}

void AuthService::logout() {
    authToken_.clear();
    accelerationKeyId_.clear();
}

