#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

ACTION=$1
shift 1

# Parse arguments
while getopts "n:c:p:e:" opt; do
    case $opt in
        n ) NAME=${OPTARG} ;;
        c ) CONFIG=${OPTARG} ;;
        p ) PROXY=${OPTARG} ;;
        e ) EPOCH=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

ROOT=$(dirname "$(readlink -f "$0")")
TASKSET="taskset --cpu-list 2-19,22-39"
ECHO_BIN="target/release/echo"
ENVOY_BIN="/local/home/laurinb/envoy/bazel-out/k8-opt/bin/source/exe/envoy-static"
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}

function stop_probes {
    sudo killall -SIGINT funclatency-bpfcc >/dev/null 2>&1
}

function stop_experiment {
    stop_probes
    sudo pkill envoy-static >/dev/null 2>&1
    sudo pkill echo >/dev/null 2>&1
}
trap stop_experiment INT

case $ACTION in
    up)
        cargo b -r -p echo

        mkdir -p ${SUMMARY_DIR}

        sudo -b ${TASKSET_SERVICE} ${ENVOY_BIN} -c ${ENVOY_CONFIG} >/dev/null 2>&1
        sleep 0.25
        ENVOY_PID=$(pidof envoy-static)
        echo -e "${COLOR_GREEN}Launched envoy: ${ENVOY_PID}${COLOR_OFF}"

        sudo -b ${TASKSET_SERVICE} ${ECHO_BIN} -a 127.0.0.1:8000 -H "signature: server1" >/dev/null 2>&1
        sleep 0.25
        ECHO_PID=$(pidof echo)
        echo -e "${COLOR_GREEN}Launched echo service: ${ECHO_PID}${COLOR_OFF}"

        echo -e "${COLOR_YELLOW}Attaching probes...${COLOR_OFF}"
        sudo -b funclatency-bpfcc -p ${ENVOY_PID} ${ENVOY_BIN}:"*BalsaParser*execute*" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.parse-${EPOCH}.log 2>/dev/null
        sudo -b funclatency-bpfcc -p ${ENVOY_PID} ${ENVOY_BIN}:"*onReadReady*" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.user-${EPOCH}.log 2>/dev/null
        sudo -b funclatency-bpfcc -p ${ENVOY_PID} "process_backlog" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.ipc-${EPOCH}.log 2>/dev/null
        sudo -b funclatency-bpfcc -p ${ENVOY_PID} "ep_send_events" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.epoll-${EPOCH}.log 2>/dev/null
        sudo -b funclatency-bpfcc -p ${ENVOY_PID} -r "^vfs_writev?$" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.write-${EPOCH}.log 2>/dev/null
        sudo -b funclatency-bpfcc -p ${ENVOY_PID} -r "^vfs_readv?$" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.read-${EPOCH}.log 2>/dev/null

        sudo -b funclatency-bpfcc -p ${ECHO_PID} "process_backlog" > ${SUMMARY_DIR}/${PROXY}-bpf-svc.ipc-${EPOCH}.log 2>/dev/null
        sudo -b funclatency-bpfcc -p ${ECHO_PID} -r "^vfs_writev?$" > ${SUMMARY_DIR}/${PROXY}-bpf-svc.write-${EPOCH}.log 2>/dev/null
        sudo -b funclatency-bpfcc -p ${ECHO_PID} -r "^vfs_readv?$" > ${SUMMARY_DIR}/${PROXY}-bpf-svc.read-${EPOCH}.log 2>/dev/null
    ;;
    down)
        stop_experiment
    ;;
    *)
        echo "Invalid action: $ACTION"
        ;;
esac
