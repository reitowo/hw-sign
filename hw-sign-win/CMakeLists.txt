cmake_minimum_required(VERSION 3.15)
project(hw_sign_win)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include vcpkg toolchain
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake")

# Add executable
add_executable(hw_sign_win main.cpp)

# Link CPR library
find_package(cpr CONFIG REQUIRED)
target_link_libraries(hw_sign_win PRIVATE cpr::cpr)