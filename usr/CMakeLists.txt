cmake_minimum_required(VERSION 3.27)

get_filename_component(context_name ${CMAKE_CURRENT_BINARY_DIR} NAME)
project(${context_name})

get_property(INCLUDE_SKEL GLOBAL PROPERTY "INCLUDE_SKEL_H" ) 
include_directories(${INCLUDE_SKEL})

add_executable(${PROJECT_NAME} iscsi_usr.cpp)
target_link_libraries(${PROJECT_NAME} common bpf)
