cmake_minimum_required(VERSION 3.15)
project(hw_sign_win)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include vcpkg toolchain
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake")

# Find dependencies
find_package(cpr CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

# Add executable
add_executable(hw_sign_win WIN32 main.cpp)

# Link libraries
target_link_libraries(hw_sign_win PRIVATE 
    cpr::cpr
    nlohmann_json::nlohmann_json
    bcrypt
)

find_package(OpenSSL REQUIRED)
target_link_libraries(hw_sign_win PRIVATE OpenSSL::SSL)
target_link_libraries(hw_sign_win PRIVATE OpenSSL::Crypto)