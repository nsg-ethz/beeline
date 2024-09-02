#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

// SEC("uprobe//bin/bash:readline")
// int BPF_KRETPROBE(printret, const void *ret) {
int syscall__connect(struct pt_regs *ctx, int sockfd, const struct sockaddr *addr, int addrlen) {
     if (!addr) return 0;

    __u64 task = bpf_get_current_pid_tgid();
    __u32 tgid = task >> 32;
    __u32 pid = task;
    char str[addrlen];
    char comm[TASK_COMM_LEN];

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_probe_read_user_str(str, sizeof(str), addr);

    bpf_trace_printk("uretprobe | pid: %d, tgid: %d, comm: %s, read: %s", pid, tgid, comm, str);

    return 0;
}