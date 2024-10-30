cmake_minimum_required(VERSION 3.12)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(PICO_BOARD pico_w)
set(PICO_CYW43_SUPPORTED_1)

SET(ProjectName tcp_client)

include(pico_sdk_import.cmake)
#later include the freertos kernel here

project(${ProjectName})

pico_sdk_init()

add_subdirectory(src)
#add later

#add_subdirectory(lib)
