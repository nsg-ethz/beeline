#!/bin/bash

SIZE_LIST="128 256 512 1024 2048 4096 8192"

# Parse arguments
while getopts ":n:p:s:" opt; do
    case $opt in
        n ) NAME=${OPTARG} ;;
        p ) PROXY=${OPTARG} ;;
        s ) SIZE_LIST=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

if [ -z ${NAME} ] || [ -z ${PROXY} ]
then
   echo "Some or all of the parameters are empty";
   exit
fi

cleanup() {
    echo "Enable Intel HyperThreading"
    echo on | sudo tee /sys/devices/system/cpu/smt/control
    
    echo "Disable CPU performance governor"
    sudo cpupower frequency-set --governor ondemand
    
    if [ ! -z "$ENVOY_PID" ]; then
        echo "Kill envoy"
        kill $ENVOY_PID
    fi

    if [ ! -z "$EBPF_PID" ]; then
        echo "Kill ebpf"
        kill $EBPF_PID
    fi
}

# Define the trap to call the cleanup function
trap cleanup EXIT

ROOT=$(dirname "$(readlink -f "$0")")
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}

mkdir -p ${SUMMARY_DIR}

echo "Disable Intel HyperThreading"
echo off | sudo tee /sys/devices/system/cpu/smt/control

echo "Enable CPU performance governor"
sudo cpupower frequency-set --governor performance

for SIZE in ${SIZE_LIST}; do
    # this needs to be on a different NUMA node than the proxy
    CMD="PAYLOAD_SIZE=${SIZE} taskset --cpu-list 2-47 k6 run --summary-export=${SUMMARY_DIR}/stress-${PROXY}-${SIZE}B.json bench/stress.js"
    echo ${CMD}
    eval ${CMD}
done

cleanup
