cmake_minimum_required(VERSION 3.27)

project(storprototrace)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/bpf)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/usr)

set(CMAKE_VERBOSE_MAKEFILE ON)

add_subdirectory(common)
add_subdirectory(bpf)
add_subdirectory(usr)

enable_testing()
add_subdirectory(test)

