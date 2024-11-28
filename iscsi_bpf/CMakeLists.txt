cmake_minimum_required(VERSION 3.27)

get_filename_component(context_name ${CMAKE_CURRENT_BINARY_DIR} NAME)
project(${context_name})

include_directories(${CMAKE_CURRENT_BINARY_DIR})
set(VMLINUX_PATH "/sys/kernel/btf/vmlinux")
find_program(BPFTOOL_COMMAND bpftool)
set(CMAKE_C_COMPILER "clang")

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
        set(CLANG_BPF_TARGET "__TARGET_ARCH_x86")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
        set(CLANG_BPF_TARGET "__TARGET_ARCH_arm")
else()
        message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

add_custom_command(OUTPUT vmlinux.h
        COMMENT "Calling bpftool to generate vmlinux.h"
        COMMAND ${BPFTOOL_COMMAND} btf dump file ${VMLINUX_PATH} format c > vmlinux.h
        VERBATIM
)
add_custom_target(${PROJECT_NAME}vmlinux
        DEPENDS vmlinux.h
)

add_library(${PROJECT_NAME}.bpf.o STATIC iscsi_stats.bpf.c)
add_dependencies(${PROJECT_NAME}.bpf.o ${PROJECT_NAME}vmlinux)
target_compile_options(
        ${PROJECT_NAME}.bpf.o
        PRIVATE -g -O2 -target bpf -D${CLANG_BPF_TARGET} -c -fno-asynchronous-unwind-tables
)
add_custom_command(TARGET ${PROJECT_NAME}.bpf.o
        PRE_LINK
        COMMAND ${CMAKE_COMMAND} -E create_hardlink $<TARGET_OBJECTS:${PROJECT_NAME}.bpf.o> iscsi_stats.bpf.o
        COMMENT "Calling bpftool to generate iscsi_stats.skel.h"
        COMMAND ${BPFTOOL_COMMAND} gen skeleton iscsi_stats.bpf.o > iscsi_stats.skel.h
        COMMAND ${CMAKE_COMMAND} -E rm -f iscsi_stats.bpf.o
        VERBATIM
)

add_library(${PROJECT_NAME} STATIC iscsi_stats_ebpf.cpp)
add_dependencies(${PROJECT_NAME} ${PROJECT_NAME}.bpf.o)

