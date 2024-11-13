HEADERS = $(wildcard $(COMMON)/*.h)

build: ../storprototrace

../storprototrace: iscsi_usr.c $(COMMON)/common.c  $(HEADERS)
	$(CLANG) -g -O3 -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -DVERSION=\"$(VERSION)\" -o $@ iscsi_usr.c $(COMMON)/common.c   $(LIBBPF_LIBS)
