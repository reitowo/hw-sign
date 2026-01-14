#pragma once

#include "app/hardware_key.h"

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>

#include <string>

class AuthService {
public:
    AuthService();

    bool register_(const std::string& username, const std::string& password);
    bool login(const std::string& username, const std::string& password);
    bool isAuthenticated();
    void logout();

private:
    HardwareKey hardwareKey_;
    std::string authToken_;
    std::string accelerationKeyId_;
    std::string baseUrl_ = "https://dbcs-api.ovo.fan";
    cpr::Session session_;
};

