#include "common/base64.h"

std::string base64Encode(const std::vector<uint8_t>& data) {
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

std::vector<uint8_t> base64Decode(std::string_view input) {
    static constexpr std::string_view ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> result;
    std::vector<int> T(256, -1);
    for (size_t i = 0; i < 64; i++) T[static_cast<unsigned char>(ALPHABET[i])] = static_cast<int>(i);

    uint32_t val = 0;
    int valb = -8;
    for (char c : input) {
        const int tc = T[static_cast<unsigned char>(c)];
        if (tc == -1) break;
        val = (val << 6) + static_cast<uint32_t>(tc);
        valb += 6;
        if (valb >= 0) {
            result.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return result;
}

