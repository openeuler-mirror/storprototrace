CLANG ?= clang

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
BPFTOOL ?= /usr/sbin/bpftool

TOP := $(PWD)
IO_USR := $(TOP)/usr
IO_BPF := $(TOP)/bpf
COMMON := $(TOP)/common

LIBBPF_INCLUDES += -I /usr/include/bpf \
		   -I $(COMMON)/

LIBBPF_LIBS = -L /usr/lib64 -lbpf -lelf -lz

VERSION = "1.0.0"

INCLUDES=$(LIBBPF_INCLUDES)


CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

export

all: storprototrace

storprototrace: $(IO_USR) $(COMMON)/common.h $(COMMON)/iscsi_stats.skel.h
	make -C $(IO_USR)

$(COMMON)/iscsi_stats.skel.h: $(COMMON)/common.h $(IO_BPF)/iscsi_stats.bpf.c
	make -C $(IO_BPF)


.PHONY: clean
clean:
	make -C $(IO_BPF) clean
	make -C $(COMMON) clean
	rm -rf storprototrace
