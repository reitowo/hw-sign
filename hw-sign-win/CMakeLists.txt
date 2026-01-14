cmake_minimum_required(VERSION 3.15)
project(hw_sign_win)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include vcpkg toolchain
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake")

# Find dependencies
find_package(cpr CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# Add main executable
add_executable(hw_sign_win WIN32
    main.cpp
    app/auth_service.cpp
    app/hardware_key.cpp
    app/main_window.cpp
    app/ncrypt_utils.cpp
    app/openssl_demo.cpp
    common/base64.cpp
)

# Add test executable (console application)
add_executable(test_client
    test_client/main.cpp
)

# Allow includes like "app/..." / "common/..." from any subdirectory source file.
target_include_directories(hw_sign_win PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(test_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Ensure UTF-8 source decoding on MSVC/clang-cl (we have non-ASCII literals in code & logs).
if (MSVC)
    target_compile_options(hw_sign_win PRIVATE /utf-8)
    target_compile_options(test_client PRIVATE /utf-8)
endif()

# Link libraries to main executable
target_link_libraries(hw_sign_win PRIVATE 
    cpr::cpr
    nlohmann_json::nlohmann_json
    bcrypt
    ncrypt
    crypt32
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Link libraries to test executable
target_link_libraries(test_client PRIVATE 
    cpr::cpr
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
    bcrypt
    ncrypt
    crypt32
    tbs
)