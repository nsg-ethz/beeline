# generate vmlinux.h
# bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

echo Compile BPF
clang -I /usr/include/x86_64-linux-gnu/ -target bpf -Wall -O3 -D__TARGET_ARCH_x86 -c uprobe.bpf.c -o uprobe.o

