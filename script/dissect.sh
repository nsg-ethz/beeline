#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

# Parse arguments
while getopts "dln:p:r:s:u:" opt; do
    case $opt in
        n ) NAME=${OPTARG} ;;
        p ) PROXY=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

ROOT=$(dirname "$(readlink -f "$0")")
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}
SOCIAL_NETWORK_DIR=${ROOT}/../social_network
TASKSET_LOAD_GEN="taskset --cpu-list 7-40"
TASKSET_SERVICE="taskset --cpu-list 1-6"
ECHO_BIN="target/release/echo"
ENVOY_BIN="/local/home/laurinb/envoy/bazel-out/k8-opt/bin/source/exe/envoy-static"
ENVOY_CONFIG="config/dissect-http1.yaml"

cargo b -r -p echo

mkdir -p ${SUMMARY_DIR}

# sudo -b ${TASKSET_SERVICE} ${ENVOY_BIN} -c ${ENVOY_CONFIG} >/dev/null 2>&1
# sleep 0.25
# ENVOY_PID=$(pidof envoy-static)
# echo -e "${COLOR_GREEN}Launched envoy: ${ENVOY_PID}${COLOR_OFF}"

sudo -b ${TASKSET_SERVICE} ${ECHO_BIN} -a 127.0.0.1:8000 -H "signature: server1" >/dev/null 2>&1
sleep 0.25
ECHO_PID=$(pidof echo)
echo -e "${COLOR_GREEN}Launched echo service: ${ECHO_PID}${COLOR_OFF}"

# docker run --name=echo --rm -d --cpuset-cpus="1-30" -p 8001-8010:8001-8010 kalmhq/echoserver:latest
# sleep 5
# echo -e "${COLOR_GREEN}Launched echo service: ${ECHO_PID}${COLOR_OFF}"

function stop_probes {
    sudo killall -SIGINT funclatency-bpfcc >/dev/null 2>&1
}

function stop_experiment {
    stop_probes
    sudo kill ${ENVOY_PID} >/dev/null 2>&1
    sudo kill ${ECHO_PID} >/dev/null 2>&1
    # docker kill echo
}
trap stop_experiment INT

for i in {1..1} ; do
    # SIZE=$(( i * 512 ))
    RATE=$(( i * 1000 ))

    # echo -e "${COLOR_YELLOW}Attaching probes...${COLOR_OFF}"
    # sudo -b funclatency-bpfcc -p ${ENVOY_PID} ${ENVOY_BIN}:"*BalsaParser*execute*" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.parse-${RATE}.log 2>/dev/null
    # sudo -b funclatency-bpfcc -p ${ENVOY_PID} ${ENVOY_BIN}:"*onReadReady*" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.user-${RATE}.log 2>/dev/null
    # sudo -b funclatency-bpfcc -p ${ENVOY_PID} "process_backlog" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.ipc-${RATE}.log 2>/dev/null
    # sudo -b funclatency-bpfcc -p ${ENVOY_PID} "ep_send_events" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.epoll-${RATE}.log 2>/dev/null
    # sudo -b funclatency-bpfcc -p ${ENVOY_PID} -r "^vfs_writev?$" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.write-${RATE}.log 2>/dev/null
    # sudo -b funclatency-bpfcc -p ${ENVOY_PID} -r "^vfs_readv?$" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.read-${RATE}.log 2>/dev/null

    # sudo -b funclatency-bpfcc -p ${ECHO_PID} "process_backlog" > ${SUMMARY_DIR}/${PROXY}-bpf-svc.ipc-${RATE}.log 2>/dev/null
    # sudo -b funclatency-bpfcc -p ${ECHO_PID} -r "^vfs_writev?$" > ${SUMMARY_DIR}/${PROXY}-bpf-svc.write-${RATE}.log 2>/dev/null
    # sudo -b funclatency-bpfcc -p ${ECHO_PID} -r "^vfs_readv?$" > ${SUMMARY_DIR}/${PROXY}-bpf-svc.read-${RATE}.log 2>/dev/null

    # sleep 5

    BENCH_CMD="PAYLOAD_SIZE=100 BACKEND=1 ${TASKSET_LOAD_GEN} wrk -d 30s -R ${RATE} -t 10 -c 100 -s wrk/rps.lua http://127.0.0.1:9999 > ${SUMMARY_DIR}/${PROXY}-wrk-${RATE}.log"
    # BENCH_CMD="RATE=1000 PAYLOAD_SIZE=${SIZE} BACKEND=1 ${TASKSET_LOAD_GEN} k6 run --insecure-skip-tls-verify -d 30s --summary-export=${SUMMARY_DIR}/${PROXY}-k6-${SIZE}B.log k6/rps.js"
    echo ${BENCH_CMD}
    eval ${BENCH_CMD}
    RET=$?

    if [ ${RET} -ne 0 ]; then
        stop_experiment
        exit $?
    fi

    stop_probes
done

stop_experiment
