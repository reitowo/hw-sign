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

# Use pre-built TpmAtt library from TSS.MSR submodule
add_library(TpmAtt SHARED IMPORTED)

# Set properties for imported library
set_target_properties(TpmAtt PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/TSS.MSR/PCPTool.v11/x64/Debug/TpmAtt.dll"
    IMPORTED_IMPLIB "${CMAKE_CURRENT_SOURCE_DIR}/TSS.MSR/PCPTool.v11/x64/Debug/TpmAtt.lib"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/TSS.MSR/PCPTool.v11/inc"
)

# Add main executable
add_executable(hw_sign_win main.cpp)

# Copy the DLL to the output directory
add_custom_command(TARGET hw_sign_win POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_CURRENT_SOURCE_DIR}/TSS.MSR/PCPTool.v11/x64/Debug/TpmAtt.dll"
    $<TARGET_FILE_DIR:hw_sign_win>
)

# Link libraries to main executable
target_link_libraries(hw_sign_win PRIVATE 
    cpr::cpr
    nlohmann_json::nlohmann_json
    bcrypt
    OpenSSL::SSL
    OpenSSL::Crypto
    TpmAtt  # Link the TpmAtt library
)