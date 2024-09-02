# sockmap bug trace 2

Setup: 
* eBPF without connection reuse pool
* client requestin /server1

## tshark trace on lo

```
 ** (tshark:44281) 09:19:04.883826 [Main MESSAGE] -- Capture started.
 ** (tshark:44281) 09:19:04.883987 [Main MESSAGE] -- File: "/tmp/wireshark_loA2R4L2.pcapng"
1	0	0.000000000	127.0.0.1	127.0.0.1	55998 → 3000 [SYN] Seq=0 Win=65495 Len=0 MSS=65495 SACK_PERM=1 TSval=112460103 TSecr=0 WS=128
2	0	0.000061920	127.0.0.1	127.0.0.1	3000 → 55998 [SYN, ACK] Seq=0 Ack=1 Win=65483 Len=0 MSS=65495 SACK_PERM=1 TSval=112460103 TSecr=112460103 WS=128
3	0	0.000080550	127.0.0.1	127.0.0.1	55998 → 3000 [ACK] Seq=1 Ack=1 Win=65536 Len=0 TSval=112460103 TSecr=112460103
4	0	0.000195570	127.0.0.1	127.0.0.1	GET /server1 HTTP/1.1 
5	0	0.000241480	127.0.0.1	127.0.0.1	3000 → 55998 [ACK] Seq=1 Ack=68 Win=65536 Len=0 TSval=112460103 TSecr=112460103
6	0	0.001046110	127.0.0.1	127.0.0.1	HTTP/1.1 200 OK  [TCP segment of a reassembled PDU]
7	0	0.001059190	127.0.0.1	127.0.0.1	55998 → 3000 [ACK] Seq=68 Ack=73 Win=65536 Len=0 TSval=112460104 TSecr=112460104
8	0	0.001075680	127.0.0.1	127.0.0.1	HTTP/1.1 200 OK 
9	0	0.001084390	127.0.0.1	127.0.0.1	55998 → 3000 [ACK] Seq=68 Ack=76 Win=65536 Len=0 TSval=112460104 TSecr=112460104
10	0	1.001320383	127.0.0.1	127.0.0.1	GET /server1 HTTP/1.1 
11	0	1.042887936	127.0.0.1	127.0.0.1	3000 → 55998 [ACK] Seq=76 Ack=135 Win=65536 Len=0 TSval=112461146 TSecr=112461104
```
The server acks the packet, but doesn't seem to redirect it to backend.

## BPF trace
```
           <...>-44321   [005] b.s21 71757.754910: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:55998] op: 2
           <...>-44321   [005] b.s21 71757.754934: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:55998] op: 1
           <...>-44321   [005] b.s21 71757.754940: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:55998] op: 6
           <...>-44321   [005] ..s31 71757.754980: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:55998] op: 5
           <...>-44321   [005] ..s31 71757.754982: bpf_trace_printk: Add socket with key [0.0.0.0:55998->0]
           <...>-44321   [005] ..s31 71757.754993: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:55998] op: 10
           <...>-44321   [005] ..s31 71757.754996: bpf_trace_printk: Socket with key [0.0.0.0:55998] changed state 3 | 1 | 0 | 0
           a.out-44321   [005] b.s41 71757.755093: bpf_trace_printk: Parse packet: local [0.0.0.0:3000] remote: [0.0.0.0:55998]
           a.out-44321   [005] b.s41 71757.755105: bpf_trace_printk: Process packet: local [0.0.0.0:3000] remote: [0.0.0.0:55998]
           a.out-44321   [005] b.s41 71757.755110: bpf_trace_printk: Data: GET /server1 HTTP/1.1
Host: 127.0.0.1:8000
User-Agent: client
           a.out-44321   [005] b.s41 71757.755113: bpf_trace_printk: Received HTTP request
      ebpf_proxy-44222   [001] ...11 71757.755233: bpf_trace_printk: Process sockops: local [0.0.0.0:42558] remote: [0.0.0.0:8000] op: 3
      ebpf_proxy-44222   [001] ...11 71757.755249: bpf_trace_printk: Process sockops: local [0.0.0.0:42558] remote: [0.0.0.0:8000] op: 2
      ebpf_proxy-44222   [001] ...11 71757.755252: bpf_trace_printk: Process sockops: local [0.0.0.0:42558] remote: [0.0.0.0:8000] op: 1
      ebpf_proxy-44222   [001] ...11 71757.755257: bpf_trace_printk: Process sockops: local [0.0.0.0:42558] remote: [0.0.0.0:8000] op: 6
      ebpf_proxy-44222   [001] ...11 71757.755357: bpf_trace_printk: Process sockops: local [0.0.0.0:42558] remote: [0.0.0.0:8000] op: 4
      ebpf_proxy-44222   [001] ...11 71757.755369: bpf_trace_printk: Add socket with key [0.0.0.0:42558->0]
          fortio-2915    [005] b.s41 71757.755859: bpf_trace_printk: Parse packet: local [0.0.0.0:42558] remote: [0.0.0.0:8000]
          fortio-2915    [005] b.s41 71757.755877: bpf_trace_printk: Process packet: local [0.0.0.0:42558] remote: [0.0.0.0:8000]
          fortio-2915    [005] b.s41 71757.755880: bpf_trace_printk: Data: HTTP/1.1 200 OK
Date: Tue, 09 Apr 2024 07:19:07 GMT
Content-Length: 0
          fortio-2915    [005] b.s41 71757.755884: bpf_trace_printk: Received a packet from an existing backend connection
          fortio-2915    [005] b.s41 71757.755885: bpf_trace_printk: Redirecting to connection [0.0.0.0:55998]
```
9 and 7 correspond to LAST_ACK and CLOSE. This is a connection to a backend, but unknown? Does this occur more often, where does this socket come from?
```
          <idle>-0       [003] ..s31 71759.077804: bpf_trace_printk: Process sockops: local [0.0.0.0:48828] remote: [0.0.0.0:8000] op: 10
          <idle>-0       [003] .Ns31 71759.077829: bpf_trace_printk: Socket with key [0.0.0.0:48828] changed state 9 | 7 | 0 | 0
```
Backend connection is not kept alive, so CLOSE_WAIT should be fine.
```
          fortio-4594    [001] ..s31 71787.785131: bpf_trace_printk: Process sockops: local [0.0.0.0:42558] remote: [0.0.0.0:8000] op: 10
          fortio-4594    [001] ..s31 71787.785156: bpf_trace_printk: Socket with key [0.0.0.0:42558] changed state 1 | 8 | 0 | 0
          fortio-4594    [001] ..s31 71787.785159: bpf_trace_printk: Socket with key [0.0.0.0:0] received CLOSE_WAIT
```

## client trace

Client is able to request one page, the second one times out.

```
send req...
waiting for res...
Received response (0):HTTP/1.1 200 OK
Date: Tue, 09 Apr 2024 07:19:07 GMT
Content-Length: 0


send req...
waiting for res...
```