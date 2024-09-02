from bcc import BPF
from time import sleep

b = BPF(src_file="uprobe.bpf.c")

# Attach the kprobe defined in the eBPF program to the clone system call.
connect_e = b.get_syscall_fnname("connect").decode()
b.attach_kprobe(event=connect_e, fn_name="syscall__connect")

try:
    print("Attaching probes... Press Ctrl+C to exit.")
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    pass

while 1:
    sleep(100)
    b.trace_print()