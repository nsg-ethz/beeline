#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

SEC("uprobe/read_req")
int BPF_UPROBE(uprobe_read_req) {
    __u64 task = bpf_get_current_pid_tgid();
    __u32 tgid = task >> 32;
    __u32 pid = task;

	char user_str[MAX_LINE_SIZE];
	char comm[TASK_COMM_LEN];

	// __u32 user_str_len = (addrlen > MAX_LINE_SIZE) ? MAX_LINE_SIZE : addrlen;

	// __u32 user_str_len = addrlen;
    // bpf_get_current_comm(&comm, sizeof(comm));
    // bpf_probe_read_user_str(user_str, user_str_len, addr);

    bpf_printk("uprobe | pid: %d, tgid: %d, comm: %s", pid, tgid, comm);

    return 0;
}