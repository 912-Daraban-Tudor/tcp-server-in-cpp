cmake_minimum_required(VERSION 3.15)
project(QST LANGUAGES CXX)

if (WIN32)
    add_compile_definitions(NOMINMAX)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Optional: add sanitizer flags when building Debug (useful locally)
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer")
    endif()
endif()

# Warning flags (platform-aware)
if (MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(Threads REQUIRED)

# small library for the FrameParser
add_library(frame_parser
        src/frame_parser.cpp
)

target_include_directories(frame_parser
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# main executable (your src/main.cpp)
add_executable(QST
        src/main.cpp
)

target_link_libraries(QST
        PRIVATE frame_parser Threads::Threads
)

# test executable for the parser
add_executable(test_frame_parser
        test/test_frame_parser.cpp
)

target_link_libraries(test_frame_parser
        PRIVATE frame_parser Threads::Threads
)


# server
add_executable(server_qst src/server.cpp)
target_link_libraries(server_qst PRIVATE frame_parser Threads::Threads)
if (WIN32)
    target_link_libraries(server_qst PRIVATE ws2_32)
endif()

# demo client
add_executable(client_demo src/client_demo.cpp)
if (WIN32)
    target_link_libraries(client_demo PRIVATE ws2_32)
endif()

# (optional) put binaries in build/bin
set_target_properties(server_qst client_demo PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
)


add_executable(client_login_echo src/client_login_echo.cpp)
if (WIN32)
    target_link_libraries(client_login_echo PRIVATE ws2_32)
endif()
set_target_properties(client_login_echo PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin")
