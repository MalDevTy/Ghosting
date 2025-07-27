cmake_minimum_required(VERSION 3.31)
project(Ghosting C)

set(CMAKE_C_STANDARD 99)

add_executable(Ghosting main.c
        ntapi_defs.h)

# Link WinHTTP library
target_link_libraries(Ghosting winhttp)
# Link userenv library
target_link_libraries(Ghosting userenv)