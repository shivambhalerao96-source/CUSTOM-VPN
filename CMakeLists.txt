cmake_minimum_required(VERSION 3.16)
project(CustomVPN VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)

# Prefer pkg-config, but keep a portable CMake fallback for systems that do
# not ship a libsodium .pc file.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(SODIUM QUIET IMPORTED_TARGET libsodium)
endif()

if(TARGET PkgConfig::SODIUM)
    add_library(CustomVPN::Sodium ALIAS PkgConfig::SODIUM)
else()
    find_path(SODIUM_INCLUDE_DIR NAMES sodium.h REQUIRED)
    find_library(SODIUM_LIBRARY NAMES sodium REQUIRED)

    add_library(customvpn_sodium UNKNOWN IMPORTED)
    set_target_properties(customvpn_sodium PROPERTIES
        IMPORTED_LOCATION "${SODIUM_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
    )
    add_library(CustomVPN::Sodium ALIAS customvpn_sodium)
endif()

add_library(vpn_core_objects OBJECT
    crypto/handshake.cpp
    crypto/session_keys.cpp
    crypto/packet_crypto.cpp
    crypto/replay_protection.cpp
    tun/setup.cpp
)

target_include_directories(vpn_core_objects
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/tun
)

target_link_libraries(vpn_core_objects
    PUBLIC
        CustomVPN::Sodium
        Threads::Threads
)

add_executable(vpn_client
    client/client1.cpp
    client/transport.cpp
    client/disconnect.cpp
    $<TARGET_OBJECTS:vpn_core_objects>
)
target_link_libraries(vpn_client PRIVATE CustomVPN::Sodium Threads::Threads)
target_include_directories(vpn_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/client)

add_executable(vpn_server
    server/server.cpp
    server/forward.cpp
    $<TARGET_OBJECTS:vpn_core_objects>
)
target_link_libraries(vpn_server PRIVATE CustomVPN::Sodium Threads::Threads)
target_include_directories(vpn_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/server)

option(BUILD_FRONTEND "Build the Qt frontend application" ON)
if(BUILD_FRONTEND)
    find_package(QT NAMES Qt6 Qt5 COMPONENTS Widgets REQUIRED)
    find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Widgets REQUIRED)

    add_executable(vpn_frontend frontend/app.cpp)
    target_link_libraries(vpn_frontend PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)
    set_target_properties(vpn_frontend PROPERTIES
        AUTOMOC ON
        AUTOUIC ON
        AUTORCC ON
    )
endif()

set_target_properties(vpn_client PROPERTIES OUTPUT_NAME vpn_client)
set_target_properties(vpn_server PROPERTIES OUTPUT_NAME vpn_server1)
set_target_properties(vpn_frontend PROPERTIES OUTPUT_NAME vpn_frontend)

set_target_properties(vpn_client vpn_server vpn_frontend PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)
