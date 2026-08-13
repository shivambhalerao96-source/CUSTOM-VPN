cmake_minimum_required(VERSION 3.10)
project(client_project CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(cl
    client1.cpp
    transport.cpp
    ../tun/setup.cpp
)

add_custom_target(run
    COMMAND sudo $<TARGET_FILE:cl>
    DEPENDS cl
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running cl with sudo..."
)