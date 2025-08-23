cmake_minimum_required(VERSION 3.16)
project(obSecure)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)

find_path(CRYPTOPP_INCLUDE_DIR cryptopp/config.h)
find_library(CRYPTOPP_LIBRARY NAMES cryptopp crypto++)

if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR "Crypto++ library not found. Please install Crypto++ development package.")
endif()

qt6_standard_project_setup()

set(SOURCES
    src/main.cpp
    src/core/KeyManager.cpp
    src/core/CryptoManager.cpp
    src/core/UserManager.cpp
    src/core/MessageProtocol.cpp
    src/network/NetworkManager.cpp
    src/gui/MainWindow.cpp
)

set(HEADERS
    src/core/KeyManager.h
    src/core/CryptoManager.h
    src/core/UserManager.h
    src/core/MessageProtocol.h
    src/network/NetworkManager.h
    src/gui/MainWindow.h
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
    src/core
    src/network
    src/gui
)

set_target_properties(obSecure PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
