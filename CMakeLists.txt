cmake_minimum_required(VERSION 3.31)
project(Ghosting C)

set(CMAKE_C_STANDARD 99)

# Add PHNT include path
include_directories(${CMAKE_SOURCE_DIR}/phnt)

add_executable(Ghosting main.c
        ntapi_defs.h)

# Link WinHTTP library
target_link_libraries(Ghosting winhttp)
target_link_libraries(Ghosting userenv)