cmake_minimum_required(VERSION 3.27)

get_filename_component(context_name ${CMAKE_CURRENT_BINARY_DIR} NAME)
project(${context_name})

add_library(${PROJECT_NAME} STATIC common.cpp)

