cmake_minimum_required(VERSION 3.16)

project(samloader VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

add_executable(samloader
    src/main.cpp
    src/auth.cpp
    src/xml.cpp
    src/fus_client.cpp
    src/downloader.cpp
)

target_include_directories(samloader PRIVATE include)
target_link_libraries(samloader PRIVATE OpenSSL::Crypto CURL::libcurl)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(samloader PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(samloader PRIVATE /W4 /permissive-)
endif()
