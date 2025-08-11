cmake_minimum_required(VERSION 3.15)
project(QST LANGUAGES CXX)

# ---- Defaults ---------------------------------------------------------------
# If user didn't specify a build type, default to Debug
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type (Debug, Release, RelWithDebInfo, MinSizeRel)" FORCE)
endif()

option(ENABLE_SANITIZERS "Enable ASan/UBSan when building Debug with GCC/Clang" OFF)

# ---- Language / warnings -----------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if (MSVC)
    add_compile_options(/W4 /permissive-)
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
add_executable(server_qst src/server.cpp)
target_link_libraries(server_qst PRIVATE frame_parser Threads::Threads)
target_include_directories(server_qst PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)


# Client (spec-correct)
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/client_login_echo.cpp")
    add_executable(client_login_echo src/client_login_echo.cpp)
    target_link_libraries(client_login_echo PRIVATE frame_parser Threads::Threads)
    target_include_directories(client_login_echo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
endif()



# ---- output dirs -------------------------------------------------------------
function(set_bin_dir target)
    if (TARGET ${target})
        set_target_properties(${target} PROPERTIES
                RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
                RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
                RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin")
    endif()
endfunction()

set_bin_dir(server_qst)
set_bin_dir(test_frame_parser)
set_bin_dir(client_login_echo)
set_bin_dir(QST)

# ---- tests -------------------------------------------------------------------
include(CTest)

# frame_parser test binary
add_executable(test_frame_parser test/test_frame_parser.cpp)
target_link_libraries(test_frame_parser PRIVATE frame_parser Threads::Threads)
target_include_directories(test_frame_parser PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# LCG test binary
add_executable(test_lcg test/test_lcg.cpp)
target_link_libraries(test_lcg PRIVATE frame_parser Threads::Threads)
target_include_directories(test_lcg PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Register tests using generator expressions so CTest finds the real path
add_test(NAME frame_parser  COMMAND $<TARGET_FILE:test_frame_parser>)
add_test(NAME lcg_keystream COMMAND $<TARGET_FILE:test_lcg>)

# (optional) put test binaries in build/bin/
set_bin_dir(test_frame_parser)
set_bin_dir(test_lcg)


add_executable(server_qst_epoll src/epoll_server.cpp)
target_link_libraries(server_qst_epoll PRIVATE frame_parser Threads::Threads)
target_include_directories(server_qst_epoll PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
set_bin_dir(server_qst_epoll)
