cmake_minimum_required (VERSION 3.27)

project(test)

find_package(GTest REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g3 -O0 --coverage")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")

add_subdirectory(../common test_common)

file(GLOB_RECURSE sources "*.cpp")
foreach(source ${sources})
        get_filename_component(name ${source} NAME_WE)
        add_executable(${name} ${source})
        target_link_libraries(${name} PRIVATE gtest)
        target_link_libraries(${name} PRIVATE test_common)
        target_link_libraries(${name} PRIVATE bpf)
        add_test(NAME ${name} COMMAND ${name})
endforeach()
