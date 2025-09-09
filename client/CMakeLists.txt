cmake_minimum_required(VERSION 3.16)
project(obSecure)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)

# Find Crypto++ with better path detection for macOS
find_path(CRYPTOPP_INCLUDE_DIR 
    NAMES cryptopp/config.h
    PATHS /usr/local/include /opt/homebrew/include
)
find_library(CRYPTOPP_LIBRARY 
    NAMES cryptopp crypto++
    PATHS /usr/local/lib /opt/homebrew/lib
)

if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR "Crypto++ library not found. Install with: brew install cryptopp")
endif()

qt6_standard_project_setup()

set(SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/KeyManager.cpp
    src/CryptoManager.cpp
    src/NetworkManager.cpp
    src/UserManager.cpp
    src/MessageProtocol.cpp
    src/X3DHManager.cpp
    src/PhoneAuthManager.cpp
    src/ServerAPI.cpp
    src/ConfigManager.cpp
)

include_directories(include)

set(HEADERS
    include/MainWindow.h
    include/KeyManager.h
    include/CryptoManager.h
    include/NetworkManager.h
    include/UserManager.h
    include/MessageProtocol.h
    include/X3DHManager.h
    include/PhoneAuthManager.h
    include/ServerAPI.h
    include/ConfigManager.h  
)

qt6_add_executable(obSecure ${SOURCES} ${HEADERS})

target_link_libraries(obSecure 
    PRIVATE
    Qt6::Core 
    Qt6::Widgets 
    Qt6::Network
    ${CRYPTOPP_LIBRARY}
)

target_include_directories(obSecure 
    PRIVATE 
    ${CRYPTOPP_INCLUDE_DIR}
)

set_target_properties(obSecure PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
