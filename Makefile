OUTPUT 		:= 	$(abspath .output)
VMLINUX 	:=  $(OUTPUT)/vmlinux
SKEL		:=  $(OUTPUT)/skel

.PHONY: all
all: bpfobj skel userspace


$(OUTPUT) $(OUTPUT)/vmlinux $(OUTPUT)/skel:
	mkdir -p $@

vmlinux: $(OUTPUT)/vmlinux
	/usr/sbin/bpftool btf dump -B /sys/kernel/btf/vmlinux file /sys/kernel/btf/vmlinux format c > $(VMLINUX)/vmlinux.h

bpfobj: $(OUTPUT)
	clang -O2 -g -c -Wall -target bpf src/ebpf/beevms.bpf.c -o $(OUTPUT)/beevms.bpf.o -D__TARGET_ARCH_x86 -mcpu=v3

skel: $(OUTPUT)/skel
	/usr/sbin/bpftool gen skeleton $(OUTPUT)/beevms.bpf.o > $(SKEL)/beevms.skel.h

userspace:
	mkdir -p build
	gcc src/beevms.c-I $(SKEL) -o build/beevms -lelf -lz -lbpf -ljansson

install:
	mkdir -p $(DESTDIR)/usr/bin
	cp build/beevms $(DESTDIR)/usr/bin/beevms

clean:
	rm -rf $(OUTPUT)
