cmake_minimum_required(VERSION 3.15)
project(QST LANGUAGES CXX)

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
