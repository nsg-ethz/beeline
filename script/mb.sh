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
        c ) PROXY_CONFIG=${OPTARG} ;;
        p ) PROXY=${OPTARG} ;;
        e ) EPOCH=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

ROOT=$(dirname "$(readlink -f "$0")")
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}

ECHO_BIN="${ROOT}/../target/release/echo"
BEELINE_BIN="${ROOT}/../target/release/beeline"
NAIVE_BIN="${ROOT}/../target/release/naive"
ENVOY_BIN="${HOME}/envoy/bazel-out/k8-opt/bin/source/exe/envoy-static"

function stop_probes {
    sudo killall -SIGINT funclatency-bpfcc >/dev/null 2>&1
}

case $ACTION in
    up)
        mkdir -p ${SUMMARY_DIR}

        CPU_SYSTEM=0,1,20,21
        CPU_BEELINE=2-19,22-39
        TASKSET="taskset -c ${CPU_BEELINE}"

        # cleanup just to be safe
        stop_probes
        sudo systemctl stop mb-proxy.scope > /dev/null 2>&1
        sudo systemctl stop mb-echo.scope > /dev/null 2>&1
        sudo systemctl stop mb-bpf-monitor.scope > /dev/null 2>&1

        echo -e "${COLOR_YELLOW}Assigning CPUs ${CPU_BEELINE} to experiment${COLOR_OFF}"
        sudo systemctl set-property --runtime user.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime system.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime init.scope AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime beeline.slice AllowedCPUs=${CPU_BEELINE}

        sudo -b -E systemd-run -q --scope -u mb-echo --slice beeline.slice ${ECHO_BIN} -a 127.0.0.1:8000 -H "signature: server1" -e conn-id > /dev/null 2>&1
        sleep 1
        ECHO_PID=$(pidof echo)
        echo -e "${COLOR_GREEN}Launched echo service${COLOR_OFF}"

        if [ "${PROXY}" = "beeline" ]; then
            BPF_PROFILE=1 sudo -b -E systemd-run -q --scope -u mb-proxy --slice beeline.slice ${BEELINE_BIN} -a 127.0.0.1:8080 -c ${PROXY_CONFIG} > /dev/null 2>&1
            sleep 5
            echo -e "${COLOR_GREEN}Launched beeline${COLOR_OFF}"

            sudo -b -E systemd-run -q --scope -u mb-bpf-monitor bpftool prog tracelog > ${SUMMARY_DIR}/${PROXY}-bpf-e${EPOCH}.log
        elif [ "${PROXY}" = "naive" ]; then
            sudo -b -E systemd-run -q --scope -u mb-proxy --slice beeline.slice ${NAIVE_BIN} -a 127.0.0.1:8080 -c ${PROXY_CONFIG} > ${SUMMARY_DIR}/${PROXY}-bpf-e${EPOCH}.log 2>&1
            sleep 5
            NAIVE_PID=$(pidof naive)
            echo -e "${COLOR_GREEN}Launched naive${COLOR_OFF}"

            echo -e "${COLOR_YELLOW}Attaching probes...${COLOR_OFF}"
            sudo -b funclatency-bpfcc -p ${NAIVE_PID} "process_backlog" > ${SUMMARY_DIR}/${PROXY}-bpf-naive.ipc-e${EPOCH}.log 2>/dev/null
            sudo -b funclatency-bpfcc -p ${NAIVE_PID} "ep_send_events" > ${SUMMARY_DIR}/${PROXY}-bpf-naive.epoll-e${EPOCH}.log 2>/dev/null
            sudo -b funclatency-bpfcc -p ${NAIVE_PID} "__sys_recvfrom" > ${SUMMARY_DIR}/${PROXY}-bpf-naive.read-e${EPOCH}.log 2>/dev/null
            sudo -b funclatency-bpfcc -p ${NAIVE_PID} "__x64_sys_writev" > ${SUMMARY_DIR}/${PROXY}-bpf-naive.write-e${EPOCH}.log 2>/dev/null
        else
            sudo -b -E systemd-run -q --scope -u mb-proxy --slice beeline.slice ${ENVOY_BIN} -c ${PROXY_CONFIG} > /dev/null 2>&1
            sleep 1
            ENVOY_PID=$(pidof envoy-static)
            echo -e "${COLOR_GREEN}Launched envoy proxy: ${ENVOY_PID}${COLOR_OFF}"

            echo -e "${COLOR_YELLOW}Attaching probes...${COLOR_OFF}"
            sudo -b funclatency-bpfcc -p ${ENVOY_PID} ${ENVOY_BIN}:"*BalsaParser*execute*" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.parse-e${EPOCH}.log 2>/dev/null
            sudo -b funclatency-bpfcc -p ${ENVOY_PID} ${ENVOY_BIN}:"*onReadReady*" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.user-e${EPOCH}.log 2>/dev/null
            sudo -b funclatency-bpfcc -p ${ENVOY_PID} "process_backlog" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.ipc-e${EPOCH}.log 2>/dev/null
            sudo -b funclatency-bpfcc -p ${ENVOY_PID} "ep_send_events" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.epoll-e${EPOCH}.log 2>/dev/null
            sudo -b funclatency-bpfcc -p ${ENVOY_PID} "__sys_sendto" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.write-e${EPOCH}.log 2>/dev/null
            sudo -b funclatency-bpfcc -p ${ENVOY_PID} "vfs_readv" > ${SUMMARY_DIR}/${PROXY}-bpf-envoy.read-e${EPOCH}.log 2>/dev/null

            sudo -b funclatency-bpfcc -p ${ECHO_PID} "process_backlog" > ${SUMMARY_DIR}/${PROXY}-bpf-svc.ipc-e${EPOCH}.log 2>/dev/null
            sudo -b funclatency-bpfcc -p ${ECHO_PID} -r "^vfs_writev?$" > ${SUMMARY_DIR}/${PROXY}-bpf-svc.write-e${EPOCH}.log 2>/dev/null
            sudo -b funclatency-bpfcc -p ${ECHO_PID} -r "^vfs_readv?$" > ${SUMMARY_DIR}/${PROXY}-bpf-svc.read-e${EPOCH}.log 2>/dev/null

            sleep 5
        fi
    ;;
    down)
        CPU_SYSTEM=0-39

        stop_probes
        sudo systemctl stop mb-proxy.scope > /dev/null 2>&1
        sudo systemctl stop mb-echo.scope > /dev/null 2>&1
        sudo systemctl stop mb-bpf-monitor.scope > /dev/null 2>&1

        if [ "${PROXY}" = "beeline" ]; then
            grep "other total" ${SUMMARY_DIR}/${PROXY}-bpf-e${EPOCH}.log > ${SUMMARY_DIR}/${PROXY}-bpf-beeline.user-e${EPOCH}.log
            grep "parse total" ${SUMMARY_DIR}/${PROXY}-bpf-e${EPOCH}.log > ${SUMMARY_DIR}/${PROXY}-bpf-beeline.parse-e${EPOCH}.log
            rm ${SUMMARY_DIR}/${PROXY}-bpf-e${EPOCH}.log
        elif [ "${PROXY}" = "naive" ]; then
            grep "other total" ${SUMMARY_DIR}/${PROXY}-bpf-e${EPOCH}.log > ${SUMMARY_DIR}/${PROXY}-bpf-naive.user-e${EPOCH}.log
            grep "parse total" ${SUMMARY_DIR}/${PROXY}-bpf-e${EPOCH}.log > ${SUMMARY_DIR}/${PROXY}-bpf-naive.parse-e${EPOCH}.log
            rm ${SUMMARY_DIR}/${PROXY}-bpf-e${EPOCH}.log
        fi

        echo -e "${COLOR_YELLOW}Resetting CPUs${COLOR_OFF}"
        sudo systemctl set-property --runtime user.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime system.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime init.scope AllowedCPUs=${CPU_SYSTEM}
    ;;
    *)
        echo "Invalid action: $ACTION"
        ;;
esac
