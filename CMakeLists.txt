cmake_minimum_required(VERSION 3.27)

project(storprototrace)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/bpf)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/usr)

set(CMAKE_VERBOSE_MAKEFILE ON)

add_subdirectory(common)
add_subdirectory(bpf)

get_property(INCLUDE_SKEL GLOBAL PROPERTY "INCLUDE_SKEL_H" )
include_directories(${INCLUDE_SKEL})

add_executable(${PROJECT_NAME} iscsi_usr.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE common bpf.bpf.o bpf)

enable_testing()
add_subdirectory(test)

