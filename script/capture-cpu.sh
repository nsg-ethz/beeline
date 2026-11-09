#!/bin/bash

# Softirq time is also charged to the task it interrupts, so the sum of all
# rows except host double counts some of it. Use the host row for the total.

while getopts "n:p:e:" opt; do
    case $opt in
        n ) NAME=${OPTARG} ;;
        p ) PROXY=${OPTARG} ;;
        e ) EPOCH=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

ROOT=$(dirname "$(readlink -f "$0")")
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}
mkdir -p ${SUMMARY_DIR}

# USER_HZ ticks to microseconds
TICK_US=$(( 1000000 / $(getconf CLK_TCK) ))

mapfile -t CONTAINERS < <(docker ps --no-trunc --filter label=com.docker.compose.service \
    --format '{{.ID}} {{.Label "com.docker.compose.service"}}')

PROCS=()
for pid in $(pidof beeline envoy l4fp); do
    # the sidecar container also runs envoy, its cgroup already covers it
    grep -q docker- /proc/${pid}/cgroup || PROCS+=("${pid} $(< /proc/${pid}/comm)")
done

FILE=${SUMMARY_DIR}/${PROXY}-cpu-e${EPOCH}.log
echo "timestamp,name,user_usec,system_usec" > ${FILE}

while sleep 1; do
    ts=${EPOCHREALTIME/./}000
    {
        for c in "${CONTAINERS[@]}"; do
            read -r id svc <<< "$c"
            { read -r _; read -r _ u; read -r _ k; } < /sys/fs/cgroup/system.slice/docker-${id}.scope/cpu.stat
            echo "${ts},${svc},${u},${k}"
        done
        for p in "${PROCS[@]}"; do
            read -r pid comm <<< "$p"
            read -r -a f < /proc/${pid}/stat
            echo "${ts},${comm},$(( f[13] * TICK_US )),$(( f[14] * TICK_US ))"
        done
        read -r _ u n k _ _ irq sirq steal _ < /proc/stat
        echo "${ts},softirq,0,$(( (irq + sirq) * TICK_US ))"
        echo "${ts},host,$(( (u + n) * TICK_US )),$(( (k + irq + sirq + steal) * TICK_US ))"
    } >> ${FILE}
done
