cmake_minimum_required(VERSION 3.15)
project(QST LANGUAGES CXX)

# ---- Defaults ---------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type (Debug, Release, RelWithDebInfo, MinSizeRel)" FORCE)
endif()
option(ENABLE_SANITIZERS "Enable ASan/UBSan when building Debug with GCC/Clang" OFF)

# ---- Language / warnings ----------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if (MSVC)
    add_compile_options(/W4 /permissive-)  # kept for portability if ever needed
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# ---- Debug helpers (GCC/Clang) ----------------------------------------------
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-fno-omit-frame-pointer -g -O0)
        if (ENABLE_SANITIZERS)
            add_compile_options(-fsanitize=address,undefined)
            add_link_options(-fsanitize=address,undefined)
        endif()
    endif()
endif()

find_package(Threads REQUIRED)

# ---- frame_parser library ----------------------------------------------------
add_library(frame_parser
        src/frame_parser.cpp
)
target_include_directories(frame_parser
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# ---- executables -------------------------------------------------------------
# Epoll server (rename the file here if yours is named differently)
add_executable(server_qst_epoll src/epoll_server.cpp)
target_link_libraries(server_qst_epoll PRIVATE frame_parser Threads::Threads)
target_include_directories(server_qst_epoll PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Client
add_executable(client_qst src/client.cpp)
target_link_libraries(client_qst PRIVATE frame_parser Threads::Threads)
target_include_directories(client_qst PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# ---- output dirs -------------------------------------------------------------
function(set_bin_dir target)
    if (TARGET ${target})
        set_target_properties(${target} PROPERTIES
                RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
                RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
                RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin")
    endif()
endfunction()

set_bin_dir(server_qst_epoll)
set_bin_dir(client_qst)

# ---- tests -------------------------------------------------------------------
include(CTest)

add_executable(test_frame_parser test/test_frame_parser.cpp)
target_link_libraries(test_frame_parser PRIVATE frame_parser Threads::Threads)
target_include_directories(test_frame_parser PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_test(NAME frame_parser COMMAND $<TARGET_FILE:test_frame_parser>)
set_bin_dir(test_frame_parser)

add_executable(test_lcg test/test_lcg.cpp)
target_link_libraries(test_lcg PRIVATE frame_parser Threads::Threads)
target_include_directories(test_lcg PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_test(NAME lcg_keystream COMMAND $<TARGET_FILE:test_lcg>)
set_bin_dir(test_lcg)
