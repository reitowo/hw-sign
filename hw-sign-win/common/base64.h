#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// NOTE: Keep legacy names to avoid touching call-sites during refactor.
std::string base64Encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> base64Decode(std::string_view input);

