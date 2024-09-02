# sockmap bug trace 1

Setup: 
* eBPF without connection reuse pool
* `fortio load -n 4 -c 2 -qps 20 http://127.0.0.1:3000/server1`
* `tshark -i veth1 -n -T fields -e frame.number -e tcp.stream -e _ws.col.Time -e ip.src -e ip.dst -e _ws.col.Info`

## tshark trace on veth1

```
Running as user "root" and group "root". This could be dangerous.
Capturing on 'veth1'
 ** (tshark:4275) 14:22:18.143322 [Main MESSAGE] -- Capture started.
 ** (tshark:4275) 14:22:18.143399 [Main MESSAGE] -- File: "/tmp/wireshark_veth1TQVTL2.pcapng"
1		0.000000000			Router Solicitation from 8e:2a:f3:12:a4:8b
2	0	66.889481497	10.0.1.254	10.0.1.1	49912 → 8000 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=4228535480 TSecr=0 WS=128
3	0	66.889529507	10.0.1.1	10.0.1.254	8000 → 49912 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM=1 TSval=4087017256 TSecr=4228535480 WS=128
4	0	66.889591217	10.0.1.254	10.0.1.1	49912 → 8000 [ACK] Seq=1 Ack=1 Win=64256 Len=0 TSval=4228535480 TSecr=4087017256
5	0	66.889741607	10.0.1.254	10.0.1.1	GET /server1 HTTP/1.1 
6	0	66.889750737	10.0.1.1	10.0.1.254	8000 → 49912 [ACK] Seq=1 Ack=86 Win=65152 Len=0 TSval=4087017256 TSecr=4228535480
7	1	66.889889117	10.0.1.254	10.0.1.1	49916 → 8000 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=4228535480 TSecr=0 WS=128
8	1	66.889898397	10.0.1.1	10.0.1.254	8000 → 49916 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM=1 TSval=4087017257 TSecr=4228535480 WS=128
9	1	66.889916527	10.0.1.254	10.0.1.1	49916 → 8000 [ACK] Seq=1 Ack=1 Win=64256 Len=0 TSval=4228535481 TSecr=4087017257
10	1	66.889949227	10.0.1.254	10.0.1.1	GET /server1 HTTP/1.1 
11	1	66.889953667	10.0.1.1	10.0.1.254	8000 → 49916 [ACK] Seq=1 Ack=86 Win=65152 Len=0 TSval=4087017257 TSecr=4228535481
12	1	66.890210647	10.0.1.1	10.0.1.254	HTTP/1.1 200 OK 
13	0	66.890219367	10.0.1.1	10.0.1.254	HTTP/1.1 200 OK 
14	1	66.890262707	10.0.1.254	10.0.1.1	49916 → 8000 [ACK] Seq=86 Ack=76 Win=64256 Len=0 TSval=4228535481 TSecr=4087017257
15	0	66.890300057	10.0.1.254	10.0.1.1	49912 → 8000 [ACK] Seq=86 Ack=76 Win=64256 Len=0 TSval=4228535481 TSecr=4087017257
```

This is where the timeout occurs. 2 requests served so far

```
16	2	69.893092615	10.0.1.254	10.0.1.1	49918 → 8000 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=4228538484 TSecr=0 WS=128
17	2	69.893121605	10.0.1.1	10.0.1.254	8000 → 49918 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM=1 TSval=4087020260 TSecr=4228538484 WS=128
18	2	69.893151795	10.0.1.254	10.0.1.1	49918 → 8000 [ACK] Seq=1 Ack=1 Win=64256 Len=0 TSval=4228538484 TSecr=4087020260
19	2	69.893242435	10.0.1.254	10.0.1.1	GET /server1 HTTP/1.1 
20	2	69.893248465	10.0.1.1	10.0.1.254	8000 → 49918 [ACK] Seq=1 Ack=86 Win=65152 Len=0 TSval=4087020260 TSecr=4228538484
21	3	69.893466555	10.0.1.254	10.0.1.1	49926 → 8000 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=4228538484 TSecr=0 WS=128
22	3	69.893476055	10.0.1.1	10.0.1.254	8000 → 49926 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM=1 TSval=4087020260 TSecr=4228538484 WS=128
23	3	69.893490635	10.0.1.254	10.0.1.1	49926 → 8000 [ACK] Seq=1 Ack=1 Win=64256 Len=0 TSval=4228538484 TSecr=4087020260
24	3	69.893538835	10.0.1.254	10.0.1.1	GET /server1 HTTP/1.1 
25	3	69.893543725	10.0.1.1	10.0.1.254	8000 → 49926 [ACK] Seq=1 Ack=86 Win=65152 Len=0 TSval=4087020260 TSecr=4228538484
26	2	69.893716916	10.0.1.1	10.0.1.254	HTTP/1.1 200 OK 
27	2	69.893748756	10.0.1.254	10.0.1.1	49918 → 8000 [ACK] Seq=86 Ack=76 Win=64256 Len=0 TSval=4228538484 TSecr=4087020260
28	3	69.893916296	10.0.1.1	10.0.1.254	HTTP/1.1 200 OK 
29	3	69.894013116	10.0.1.254	10.0.1.1	49926 → 8000 [ACK] Seq=86 Ack=76 Win=64256 Len=0 TSval=4228538485 TSecr=4087020261
```

## tshark trace on loopback
```
Running as user "root" and group "root". This could be dangerous.
Capturing on 'Loopback: lo'
 ** (tshark:4492) 14:23:43.355537 [Main MESSAGE] -- Capture started.
 ** (tshark:4492) 14:23:43.355664 [Main MESSAGE] -- File: "/tmp/wireshark_lo02I0L2.pcapng"
1	0	0.000000000	127.0.0.1	127.0.0.1	49842 → 3000 [SYN] Seq=0 Win=65495 Len=0 MSS=65495 SACK_PERM=1 TSval=44348346 TSecr=0 WS=128
2	0	0.000066060	127.0.0.1	127.0.0.1	3000 → 49842 [SYN, ACK] Seq=0 Ack=1 Win=65483 Len=0 MSS=65495 SACK_PERM=1 TSval=44348347 TSecr=44348346 WS=128
3	0	0.000087011	127.0.0.1	127.0.0.1	49842 → 3000 [ACK] Seq=1 Ack=1 Win=65536 Len=0 TSval=44348347 TSecr=44348347
4	1	0.000143451	127.0.0.1	127.0.0.1	49856 → 3000 [SYN] Seq=0 Win=65495 Len=0 MSS=65495 SACK_PERM=1 TSval=44348347 TSecr=0 WS=128
5	1	0.000188020	127.0.0.1	127.0.0.1	3000 → 49856 [SYN, ACK] Seq=0 Ack=1 Win=65483 Len=0 MSS=65495 SACK_PERM=1 TSval=44348347 TSecr=44348347 WS=128
6	1	0.000208540	127.0.0.1	127.0.0.1	49856 → 3000 [ACK] Seq=1 Ack=1 Win=65536 Len=0 TSval=44348347 TSecr=44348347
7	0	0.000228280	127.0.0.1	127.0.0.1	GET /server1 HTTP/1.1 
8	0	0.000265171	127.0.0.1	127.0.0.1	3000 → 49842 [ACK] Seq=1 Ack=86 Win=65408 Len=0 TSval=44348347 TSecr=44348347
9	1	0.000382371	127.0.0.1	127.0.0.1	GET /server1 HTTP/1.1 
10	1	0.000428951	127.0.0.1	127.0.0.1	3000 → 49856 [ACK] Seq=1 Ack=86 Win=65408 Len=0 TSval=44348347 TSecr=44348347
11	1	0.001412711	127.0.0.1	127.0.0.1	HTTP/1.1 200 OK  [TCP segment of a reassembled PDU]
12	1	0.001435341	127.0.0.1	127.0.0.1	49856 → 3000 [ACK] Seq=86 Ack=73 Win=65536 Len=0 TSval=44348348 TSecr=44348348
13	1	0.001447671	127.0.0.1	127.0.0.1	HTTP/1.1 200 OK 
14	1	0.001473701	127.0.0.1	127.0.0.1	49856 → 3000 [ACK] Seq=86 Ack=76 Win=65536 Len=0 TSval=44348348 TSecr=44348348
15	0	0.001502061	127.0.0.1	127.0.0.1	HTTP/1.1 200 OK  [TCP segment of a reassembled PDU]
16	0	0.001527131	127.0.0.1	127.0.0.1	49842 → 3000 [ACK] Seq=86 Ack=73 Win=65536 Len=0 TSval=44348348 TSecr=44348348
17	0	0.001553151	127.0.0.1	127.0.0.1	HTTP/1.1 200 OK 
18	0	0.001575781	127.0.0.1	127.0.0.1	49842 → 3000 [ACK] Seq=86 Ack=76 Win=65536 Len=0 TSval=44348348 TSecr=44348348
```

This is where the timeout occurs. Two requests sent so far. 
The client closes both connections, server responds accordingly. 
Client doesn't send a new request but is able to send FIN?

```
19	1	3.003390069	127.0.0.1	127.0.0.1	49856 → 3000 [FIN, ACK] Seq=86 Ack=76 Win=65536 Len=0 TSval=44351350 TSecr=44348348
20	0	3.003500759	127.0.0.1	127.0.0.1	49842 → 3000 [FIN, ACK] Seq=86 Ack=76 Win=65536 Len=0 TSval=44351350 TSecr=44348348
21	1	3.003520559	127.0.0.1	127.0.0.1	3000 → 49856 [FIN, ACK] Seq=76 Ack=87 Win=65536 Len=0 TSval=44351350 TSecr=44351350
22	1	3.003560929	127.0.0.1	127.0.0.1	49856 → 3000 [ACK] Seq=87 Ack=77 Win=65536 Len=0 TSval=44351350 TSecr=44351350
23	0	3.003624989	127.0.0.1	127.0.0.1	3000 → 49842 [FIN, ACK] Seq=76 Ack=87 Win=65536 Len=0 TSval=44351350 TSecr=44351350
24	0	3.003640669	127.0.0.1	127.0.0.1	49842 → 3000 [ACK] Seq=87 Ack=77 Win=65536 Len=0 TSval=44351350 TSecr=44351350
25	2	3.003696529	127.0.0.1	127.0.0.1	49862 → 3000 [SYN] Seq=0 Win=65495 Len=0 MSS=65495 SACK_PERM=1 TSval=44351350 TSecr=0 WS=128
26	2	3.003744809	127.0.0.1	127.0.0.1	3000 → 49862 [SYN, ACK] Seq=0 Ack=1 Win=65483 Len=0 MSS=65495 SACK_PERM=1 TSval=44351350 TSecr=44351350 WS=128
27	2	3.003774939	127.0.0.1	127.0.0.1	49862 → 3000 [ACK] Seq=1 Ack=1 Win=65536 Len=0 TSval=44351350 TSecr=44351350
28	3	3.004010129	127.0.0.1	127.0.0.1	49876 → 3000 [SYN] Seq=0 Win=65495 Len=0 MSS=65495 SACK_PERM=1 TSval=44351350 TSecr=0 WS=128
29	2	3.004081839	127.0.0.1	127.0.0.1	GET /server1 HTTP/1.1 
30	3	3.004085549	127.0.0.1	127.0.0.1	3000 → 49876 [SYN, ACK] Seq=0 Ack=1 Win=65483 Len=0 MSS=65495 SACK_PERM=1 TSval=44351351 TSecr=44351350 WS=128
31	3	3.004118059	127.0.0.1	127.0.0.1	49876 → 3000 [ACK] Seq=1 Ack=1 Win=65536 Len=0 TSval=44351351 TSecr=44351351
32	2	3.004128299	127.0.0.1	127.0.0.1	3000 → 49862 [ACK] Seq=1 Ack=86 Win=65408 Len=0 TSval=44351351 TSecr=44351351
33	3	3.004469529	127.0.0.1	127.0.0.1	GET /server1 HTTP/1.1 
34	3	3.004531759	127.0.0.1	127.0.0.1	3000 → 49876 [ACK] Seq=1 Ack=86 Win=65408 Len=0 TSval=44351351 TSecr=44351351
35	2	3.004890509	127.0.0.1	127.0.0.1	HTTP/1.1 200 OK  [TCP segment of a reassembled PDU]
36	2	3.004904289	127.0.0.1	127.0.0.1	49862 → 3000 [ACK] Seq=86 Ack=73 Win=65536 Len=0 TSval=44351351 TSecr=44351351
37	2	3.004914160	127.0.0.1	127.0.0.1	HTTP/1.1 200 OK 
38	2	3.004919969	127.0.0.1	127.0.0.1	49862 → 3000 [ACK] Seq=86 Ack=76 Win=65536 Len=0 TSval=44351351 TSecr=44351351
39	3	3.005288949	127.0.0.1	127.0.0.1	HTTP/1.1 200 OK  [TCP segment of a reassembled PDU]
40	3	3.005318620	127.0.0.1	127.0.0.1	49876 → 3000 [ACK] Seq=86 Ack=73 Win=65536 Len=0 TSval=44351352 TSecr=44351352
41	3	3.005349929	127.0.0.1	127.0.0.1	HTTP/1.1 200 OK 
42	3	3.005366029	127.0.0.1	127.0.0.1	49876 → 3000 [ACK] Seq=86 Ack=76 Win=65536 Len=0 TSval=44351352 TSecr=44351352
43	2	3.005863160	127.0.0.1	127.0.0.1	49862 → 3000 [FIN, ACK] Seq=86 Ack=76 Win=65536 Len=0 TSval=44351352 TSecr=44351351
44	2	3.005928430	127.0.0.1	127.0.0.1	3000 → 49862 [FIN, ACK] Seq=76 Ack=87 Win=65536 Len=0 TSval=44351352 TSecr=44351352
45	2	3.005944780	127.0.0.1	127.0.0.1	49862 → 3000 [ACK] Seq=87 Ack=77 Win=65536 Len=0 TSval=44351352 TSecr=44351352
46	3	3.005969210	127.0.0.1	127.0.0.1	49876 → 3000 [FIN, ACK] Seq=86 Ack=76 Win=65536 Len=0 TSval=44351352 TSecr=44351352
47	3	3.005998860	127.0.0.1	127.0.0.1	3000 → 49876 [FIN, ACK] Seq=76 Ack=87 Win=65536 Len=0 TSval=44351352 TSecr=44351352
48	3	3.006012770	127.0.0.1	127.0.0.1	49876 → 3000 [ACK] Seq=87 Ack=77 Win=65536 Len=0 TSval=44351352 TSecr=44351352
```

## BPF trace

```
cat trace_pipe 
           <...>-4560    [006] ...11  3641.415738: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:0] op: 11
           <...>-4586    [007] b.s21  3645.998754: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49842] op: 2
           <...>-4586    [007] b.s21  3645.998773: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49842] op: 1
           <...>-4586    [007] b.s21  3645.998779: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49842] op: 6
           <...>-4586    [007] ..s31  3645.998824: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49842] op: 5
           <...>-4586    [007] ..s31  3645.998831: bpf_trace_printk: Add socket with key [0.0.0.0:49842->0]
           <...>-4586    [007] ..s31  3645.998866: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49842] op: 10
           <...>-4586    [007] ..s31  3645.998869: bpf_trace_printk: Socket with key [0.0.0.0:49842] changed state 3 | 1 | 0 | 0
          fortio-4590    [005] b.s21  3645.998890: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49856] op: 2
          fortio-4590    [005] b.s21  3645.998896: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49856] op: 1
          fortio-4590    [005] b.s21  3645.998901: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49856] op: 6
          fortio-4590    [005] ..s31  3645.998943: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49856] op: 5
          fortio-4590    [005] ..s31  3645.998946: bpf_trace_printk: Add socket with key [0.0.0.0:49856->0]
          fortio-4590    [005] ..s31  3645.998957: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49856] op: 10
          fortio-4590    [005] ..s31  3645.998960: bpf_trace_printk: Socket with key [0.0.0.0:49856] changed state 3 | 1 | 0 | 0
          fortio-4586    [007] b.s41  3645.998960: bpf_trace_printk: Process packet: local [0.0.0.0:3000] remote: [0.0.0.0:49842]
          fortio-4586    [007] b.s41  3645.998964: bpf_trace_printk: Data: GET /server1 HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: fortio.org/fortio-1.63.
          fortio-4586    [007] b.s41  3645.998966: bpf_trace_printk: Received HTTP request
          fortio-4590    [005] bNs41  3645.999116: bpf_trace_printk: Process packet: local [0.0.0.0:3000] remote: [0.0.0.0:49856]
          fortio-4590    [005] bNs41  3645.999132: bpf_trace_printk: Data: GET /server1 HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: fortio.org/fortio-1.63.
          fortio-4590    [005] bNs41  3645.999135: bpf_trace_printk: Received HTTP request
      ebpf_proxy-4560    [003] .N.11  3645.999210: bpf_trace_printk: Process sockops: local [0.0.0.0:49912] remote: [0.0.0.0:8000] op: 3
      ebpf_proxy-4560    [003] .N.11  3645.999226: bpf_trace_printk: Process sockops: local [0.0.0.0:49912] remote: [0.0.0.0:8000] op: 2
      ebpf_proxy-4560    [003] .N.11  3645.999229: bpf_trace_printk: Process sockops: local [0.0.0.0:49912] remote: [0.0.0.0:8000] op: 1
      ebpf_proxy-4560    [003] ...11  3645.999260: bpf_trace_printk: Process sockops: local [0.0.0.0:49912] remote: [0.0.0.0:8000] op: 6
      ebpf_proxy-4560    [003] .N.11  3645.999413: bpf_trace_printk: Process sockops: local [0.0.0.0:49912] remote: [0.0.0.0:8000] op: 4
      ebpf_proxy-4560    [003] .N.11  3645.999422: bpf_trace_printk: Add socket with key [0.0.0.0:49912->0]
      ebpf_proxy-4560    [003] ...11  3645.999709: bpf_trace_printk: Process sockops: local [0.0.0.0:49916] remote: [0.0.0.0:8000] op: 3
      ebpf_proxy-4560    [003] ...11  3645.999719: bpf_trace_printk: Process sockops: local [0.0.0.0:49916] remote: [0.0.0.0:8000] op: 2
      ebpf_proxy-4560    [003] ...11  3645.999721: bpf_trace_printk: Process sockops: local [0.0.0.0:49916] remote: [0.0.0.0:8000] op: 1
      ebpf_proxy-4560    [003] ...11  3645.999724: bpf_trace_printk: Process sockops: local [0.0.0.0:49916] remote: [0.0.0.0:8000] op: 6
      ebpf_proxy-4560    [003] ...11  3645.999750: bpf_trace_printk: Process sockops: local [0.0.0.0:49916] remote: [0.0.0.0:8000] op: 4
      ebpf_proxy-4560    [003] ...11  3645.999754: bpf_trace_printk: Add socket with key [0.0.0.0:49916->0]
          fortio-2931    [004] b.s41  3646.000075: bpf_trace_printk: Process packet: local [0.0.0.0:49916] remote: [0.0.0.0:8000]
          fortio-2931    [004] b.s41  3646.000089: bpf_trace_printk: Data: HTTP/1.1 200 OK
Date: Mon, 08 Apr 2024 12:23:55 GMT
Content-Length: 0
          fortio-2931    [004] b.s41  3646.000091: bpf_trace_printk: Received a packet from an existing backend connection
          fortio-2931    [004] b.s41  3646.000093: bpf_trace_printk: Redirecting to connection [0.0.0.0:49856]
          fortio-2925    [002] b.s41  3646.000111: bpf_trace_printk: Process packet: local [0.0.0.0:49912] remote: [0.0.0.0:8000]
          fortio-2925    [002] b.s41  3646.000117: bpf_trace_printk: Data: HTTP/1.1 200 OK
Date: Mon, 08 Apr 2024 12:23:55 GMT
Content-Length: 0
          fortio-2925    [002] b.s41  3646.000120: bpf_trace_printk: Received a packet from an existing backend connection
          fortio-2925    [002] b.s41  3646.000124: bpf_trace_printk: Redirecting to connection [0.0.0.0:49842]
```

This is where the timeout occurs. The BPF program received two requests so far.

```
          fortio-4586    [007] ..s31  3649.002133: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49856] op: 10
          fortio-4586    [007] ..s31  3649.002156: bpf_trace_printk: Socket with key [0.0.0.0:49856] changed state 1 | 8 | 0 | 0
      ebpf_proxy-4560    [003] ...11  3649.002208: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49856] op: 10
      ebpf_proxy-4560    [003] ...11  3649.002212: bpf_trace_printk: Socket with key [0.0.0.0:49856] changed state 8 | 9 | 0 | 0
           <...>-4592    [001] ..s31  3649.002266: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49842] op: 10
           <...>-4592    [001] ..s31  3649.002285: bpf_trace_printk: Socket with key [0.0.0.0:49842] changed state 1 | 8 | 0 | 0
      ebpf_proxy-4560    [003] ...11  3649.002289: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49856] op: 10
      ebpf_proxy-4560    [003] ...11  3649.002290: bpf_trace_printk: Close client connection [0.0.0.0:49856]
      ebpf_proxy-4560    [003] ...11  3649.002295: bpf_trace_printk: Enqueuing connection [0.0.0.0:49916]
      ebpf_proxy-4560    [003] ...11  3649.002298: bpf_trace_printk: Socket with key [0.0.0.0:49856] changed state 9 | 7 | 0 | 0
      ebpf_proxy-4560    [003] ...11  3649.002337: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49842] op: 10
      ebpf_proxy-4560    [003] ...11  3649.002339: bpf_trace_printk: Socket with key [0.0.0.0:49842] changed state 8 | 9 | 0 | 0
      ebpf_proxy-4560    [003] ...11  3649.002367: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49842] op: 10
      ebpf_proxy-4560    [003] ...11  3649.002368: bpf_trace_printk: Close client connection [0.0.0.0:49842]
      ebpf_proxy-4560    [003] .N.11  3649.002380: bpf_trace_printk: Enqueuing connection [0.0.0.0:49912]
      ebpf_proxy-4560    [003] .N.11  3649.002381: bpf_trace_printk: Socket with key [0.0.0.0:49842] changed state 9 | 7 | 0 | 0
          fortio-4586    [007] b.s21  3649.002436: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49862] op: 2
          fortio-4586    [007] b.s21  3649.002443: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49862] op: 1
          fortio-4586    [007] b.s21  3649.002454: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49862] op: 6
          fortio-4586    [007] ..s31  3649.002526: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49862] op: 5
          fortio-4586    [007] ..s31  3649.002549: bpf_trace_printk: Add socket with key [0.0.0.0:49862->0]
          fortio-4586    [007] ..s31  3649.002564: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49862] op: 10
          fortio-4586    [007] ..s31  3649.002567: bpf_trace_printk: Socket with key [0.0.0.0:49862] changed state 3 | 1 | 0 | 0
          fortio-4592    [001] b.s21  3649.002752: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49876] op: 2
          fortio-4592    [001] b.s21  3649.002782: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49876] op: 1
          fortio-4592    [001] b.s21  3649.002794: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49876] op: 6
          fortio-4590    [005] b.s41  3649.002823: bpf_trace_printk: Process packet: local [0.0.0.0:3000] remote: [0.0.0.0:49862]
          fortio-4590    [005] b.s41  3649.002830: bpf_trace_printk: Data: GET /server1 HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: fortio.org/fortio-1.63.
          fortio-4590    [005] b.s41  3649.002832: bpf_trace_printk: Received HTTP request
          fortio-4592    [001] ..s31  3649.002864: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49876] op: 5
          fortio-4592    [001] ..s31  3649.002878: bpf_trace_printk: Add socket with key [0.0.0.0:49876->0]
          fortio-4592    [001] ..s31  3649.002895: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49876] op: 10
          fortio-4592    [001] ..s31  3649.002901: bpf_trace_printk: Socket with key [0.0.0.0:49876] changed state 3 | 1 | 0 | 0
      ebpf_proxy-4560    [003] ...11  3649.002906: bpf_trace_printk: Process sockops: local [0.0.0.0:49918] remote: [0.0.0.0:8000] op: 3
      ebpf_proxy-4560    [003] ...11  3649.002910: bpf_trace_printk: Process sockops: local [0.0.0.0:49918] remote: [0.0.0.0:8000] op: 2
      ebpf_proxy-4560    [003] ...11  3649.002912: bpf_trace_printk: Process sockops: local [0.0.0.0:49918] remote: [0.0.0.0:8000] op: 1
      ebpf_proxy-4560    [003] ...11  3649.002914: bpf_trace_printk: Process sockops: local [0.0.0.0:49918] remote: [0.0.0.0:8000] op: 6
      ebpf_proxy-4560    [003] ...11  3649.002977: bpf_trace_printk: Process sockops: local [0.0.0.0:49918] remote: [0.0.0.0:8000] op: 4
      ebpf_proxy-4560    [003] ...11  3649.002979: bpf_trace_printk: Add socket with key [0.0.0.0:49918->0]
           <...>-4593    [006] b.s41  3649.003209: bpf_trace_printk: Process packet: local [0.0.0.0:3000] remote: [0.0.0.0:49876]
           <...>-4593    [006] b.s41  3649.003233: bpf_trace_printk: Data: GET /server1 HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: fortio.org/fortio-1.63.
           <...>-4593    [006] b.s41  3649.003236: bpf_trace_printk: Received HTTP request
      ebpf_proxy-4560    [003] ...11  3649.003282: bpf_trace_printk: Process sockops: local [0.0.0.0:49926] remote: [0.0.0.0:8000] op: 3
      ebpf_proxy-4560    [003] ...11  3649.003290: bpf_trace_printk: Process sockops: local [0.0.0.0:49926] remote: [0.0.0.0:8000] op: 2
      ebpf_proxy-4560    [003] ...11  3649.003292: bpf_trace_printk: Process sockops: local [0.0.0.0:49926] remote: [0.0.0.0:8000] op: 1
      ebpf_proxy-4560    [003] ...11  3649.003294: bpf_trace_printk: Process sockops: local [0.0.0.0:49926] remote: [0.0.0.0:8000] op: 6
      ebpf_proxy-4560    [003] .N.11  3649.003327: bpf_trace_printk: Process sockops: local [0.0.0.0:49926] remote: [0.0.0.0:8000] op: 4
      ebpf_proxy-4560    [003] .N.11  3649.003328: bpf_trace_printk: Add socket with key [0.0.0.0:49926->0]
          fortio-2915    [003] b.s41  3649.003569: bpf_trace_printk: Process packet: local [0.0.0.0:49918] remote: [0.0.0.0:8000]
          fortio-2915    [003] b.s41  3649.003581: bpf_trace_printk: Data: HTTP/1.1 200 OK
Date: Mon, 08 Apr 2024 12:23:58 GMT
Content-Length: 0
          fortio-2915    [003] b.s41  3649.003582: bpf_trace_printk: Received a packet from an existing backend connection
          fortio-2915    [003] b.s41  3649.003584: bpf_trace_printk: Redirecting to connection [0.0.0.0:49862]
          fortio-2932    [001] bNs41  3649.003796: bpf_trace_printk: Process packet: local [0.0.0.0:49926] remote: [0.0.0.0:8000]
          fortio-2932    [001] bNs41  3649.003827: bpf_trace_printk: Data: HTTP/1.1 200 OK
Date: Mon, 08 Apr 2024 12:23:58 GMT
Content-Length: 0
          fortio-2932    [001] bNs41  3649.003831: bpf_trace_printk: Received a packet from an existing backend connection
          fortio-2932    [001] bNs41  3649.003834: bpf_trace_printk: Redirecting to connection [0.0.0.0:49876]
          fortio-4590    [005] ..s31  3649.004599: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49862] op: 10
          fortio-4590    [005] ..s31  3649.004620: bpf_trace_printk: Socket with key [0.0.0.0:49862] changed state 1 | 8 | 0 | 0
      ebpf_proxy-4560    [003] ...11  3649.004638: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49862] op: 10
      ebpf_proxy-4560    [003] ...11  3649.004640: bpf_trace_printk: Socket with key [0.0.0.0:49862] changed state 8 | 9 | 0 | 0
      ebpf_proxy-4560    [003] ...11  3649.004671: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49862] op: 10
      ebpf_proxy-4560    [003] ...11  3649.004676: bpf_trace_printk: Close client connection [0.0.0.0:49862]
      ebpf_proxy-4560    [003] ...11  3649.004678: bpf_trace_printk: Enqueuing connection [0.0.0.0:49918]
      ebpf_proxy-4560    [003] ...11  3649.004680: bpf_trace_printk: Socket with key [0.0.0.0:49862] changed state 9 | 7 | 0 | 0
          fortio-4590    [005] ..s31  3649.004699: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49876] op: 10
          fortio-4590    [005] ..s31  3649.004703: bpf_trace_printk: Socket with key [0.0.0.0:49876] changed state 1 | 8 | 0 | 0
      ebpf_proxy-4560    [003] ...11  3649.004712: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49876] op: 10
      ebpf_proxy-4560    [003] ...11  3649.004713: bpf_trace_printk: Socket with key [0.0.0.0:49876] changed state 8 | 9 | 0 | 0
      ebpf_proxy-4560    [003] ...11  3649.004739: bpf_trace_printk: Process sockops: local [0.0.0.0:3000] remote: [0.0.0.0:49876] op: 10
      ebpf_proxy-4560    [003] ...11  3649.004740: bpf_trace_printk: Close client connection [0.0.0.0:49876]
      ebpf_proxy-4560    [003] ...11  3649.004741: bpf_trace_printk: Enqueuing connection [0.0.0.0:49926]
      ebpf_proxy-4560    [003] ...11  3649.004743: bpf_trace_printk: Socket with key [0.0.0.0:49876] changed state 9 | 7 | 0 | 0
          fortio-2932    [001] ..s31  3676.027082: bpf_trace_printk: Process sockops: local [0.0.0.0:49916] remote: [0.0.0.0:8000] op: 10
          fortio-2915    [003] ..s31  3676.027083: bpf_trace_printk: Process sockops: local [0.0.0.0:49912] remote: [0.0.0.0:8000] op: 10
          fortio-2915    [003] ..s31  3676.027088: bpf_trace_printk: Socket with key [0.0.0.0:49912] changed state 1 | 8 | 0 | 0
          fortio-2932    [001] ..s31  3676.027098: bpf_trace_printk: Socket with key [0.0.0.0:49916] changed state 1 | 8 | 0 | 0
          fortio-2932    [001] ..s31  3679.006530: bpf_trace_printk: Process sockops: local [0.0.0.0:49918] remote: [0.0.0.0:8000] op: 10
          fortio-2932    [001] ..s31  3679.006547: bpf_trace_printk: Socket with key [0.0.0.0:49918] changed state 1 | 8 | 0 | 0
          fortio-2925    [002] ..s31  3679.006593: bpf_trace_printk: Process sockops: local [0.0.0.0:49926] remote: [0.0.0.0:8000] op: 10
          fortio-2925    [002] ..s31  3679.006599: bpf_trace_printk: Socket with key [0.0.0.0:49926] changed state 1 | 8 | 0 | 0
```

## fortio report
```
14:23:55.790 r1 [INF] scli.go:125> Starting, command="Φορτίο", version="1.63.5 h1:XUxnT4F1vJ1EXLFAn0AYwseH0UUhr+Ti1+4REJo/faI= go1.21.5 amd64 linux", go-max-procs=8
Fortio 1.63.5 running at 20 queries per second, 8->8 procs, for 4 calls: http://127.0.0.1:3000/server1
14:23:55.791 r1 [INF] httprunner.go:121> Starting http test, run=0, url="http://127.0.0.1:3000/server1", threads=2, qps="20.0", warmup="parallel", conn-reuse=""
Starting at 20 qps with 2 thread(s) [gomax 8] : exactly 4, 2 calls each (total 4 + 0)
14:23:58.794 r5 [ERR] http_client.go:1091> Read error, err={"Op":"read","Net":"tcp","Source":{"IP":"127.0.0.1","Port":49856,"Zone":""},"Addr":{"IP":"127.0.0.1","Port":3000,"Zone":""},"Err":{}}, size=75, dest={"IP":"127.0.0.1","Port":3000,"Zone":""}, url="http://127.0.0.1:3000/server1", thread=0, run=0
14:23:58.795 r6 [ERR] http_client.go:1091> Read error, err={"Op":"read","Net":"tcp","Source":{"IP":"127.0.0.1","Port":49842,"Zone":""},"Addr":{"IP":"127.0.0.1","Port":3000,"Zone":""},"Err":{}}, size=75, dest={"IP":"127.0.0.1","Port":3000,"Zone":""}, url="http://127.0.0.1:3000/server1", thread=1, run=0
14:23:58.796 r5 [INF] periodic.go:851> T000 ended after 3.005230469s : 2 calls. qps=0.6655063631993278
14:23:58.797 r6 [INF] periodic.go:851> T001 ended after 3.005624289s : 2 calls. qps=0.6654191634395592
Ended after 3.005686569s : 4 calls. qps=1.3308
14:23:58.797 r1 [INF] periodic.go:581> Run ended, run=0, elapsed=3005686569, calls=4, qps=1.3308107509462674
Aggregated Sleep Time : count 2 avg -2.8037689 +/- 7.223e-05 min -2.803841099 max -2.803696629 sum -5.60753773
# range, mid point, percentile, count
>= -2.80384 <= -2.8037 , -2.80377 , 100.00, 2
# target 50% -2.80384
WARNING 100.00% of sleep were falling behind
Aggregated Function Time : count 4 avg 1.5026258 +/- 1.501 min 0.001499491 max 3.003766198 sum 6.01050318
# range, mid point, percentile, count
>= 0.00149949 <= 0.002 , 0.00174975 , 50.00, 2
> 3 <= 3.00377 , 3.00188 , 100.00, 2
# target 50% 0.002
# target 75% 3.00188
# target 90% 3.00301
# target 99% 3.00369
# target 99.9% 3.00376
Error cases : count 2 avg 3.0036503 +/- 0.0001159 min 3.003534349 max 3.003766198 sum 6.00730055
# range, mid point, percentile, count
>= 3.00353 <= 3.00377 , 3.00365 , 100.00, 2
# target 50% 3.00353
# target 75% 3.00365
# target 90% 3.00372
# target 99% 3.00376
# target 99.9% 3.00377
# Socket and IP used for each connection:
[0]   2 socket used, resolved to 127.0.0.1:3000, connection timing : count 2 avg 0.0004329745 +/- 5.177e-05 min 0.000381209 max 0.00048474 sum 0.000865949
[1]   2 socket used, resolved to 127.0.0.1:3000, connection timing : count 2 avg 0.000448705 +/- 9.979e-05 min 0.00034892 max 0.00054849 sum 0.00089741
Connection time histogram (s) : count 4 avg 0.00044083975 +/- 7.988e-05 min 0.00034892 max 0.00054849 sum 0.001763359
# range, mid point, percentile, count
>= 0.00034892 <= 0.00054849 , 0.000448705 , 100.00, 4
# target 50% 0.000415443
# target 75% 0.000481967
# target 90% 0.000521881
# target 99% 0.000545829
# target 99.9% 0.000548224
Sockets used: 4 (for perfect keepalive, would be 2)
Uniform: false, Jitter: false, Catchup allowed: true
IP addresses distribution:
127.0.0.1:3000: 4
Code  -1 : 2 (50.0 %)
Code 200 : 2 (50.0 %)
Response Header Sizes : count 4 avg 74 +/- 1 min 73 max 75 sum 296
Response Body/Total Sizes : count 4 avg 75 +/- 0 min 75 max 75 sum 300
All done 4 calls (plus 0 warmup) 1502.626 ms avg, 1.3 qps
```