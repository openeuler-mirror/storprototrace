cmake_minimum_required(VERSION 3.27)

project(storprototrace)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/iscsi_bpf)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/usr)

set(CMAKE_VERBOSE_MAKEFILE ON)

add_subdirectory(common)
add_subdirectory(iscsi_bpf)

add_executable(${PROJECT_NAME} iscsi_usr.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE common iscsi_bpf bpf)

enable_testing()
add_subdirectory(test)

