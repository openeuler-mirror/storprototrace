build: $(COMMON)/iscsi_stats.skel.h

$(COMMON)/iscsi_stats.skel.h: iscsi_stats.bpf.o
	$(BPFTOOL) gen skeleton $^ > $@

iscsi_stats.bpf.o: iscsi_stats.bpf.c $(COMMON)/vmlinux.h $(COMMON)/common.h
	$(CLANG)  -g -O3 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $<

$(COMMON)/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

.PHONY: clean
clean:
	rm -rf  *.o
