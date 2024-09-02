#!/bin/bash

SIZE_LIST="128 256 512 1024 2048 4096 8192"
ROOT=$(dirname "$(readlink -f "$0")")
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}

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
   echo "Error: Some or all of the parameters are empty";
   exit 1
fi

if [ -z ${BACKEND_CPU} ] || [ -z ${PROXY_CPU} ]
then
   echo "Error: BACKEND_CPU or PROXY_CPU is not set"
   exit 1
fi

cleanup() {
    echo "Enable Intel HyperThreading"
    echo on | sudo tee /sys/devices/system/cpu/smt/control
    
    echo "Disable CPU performance governor"
    sudo cpupower frequency-set --governor ondemand

    echo "Reset CPU shielding"
    sudo systemctl set-property --runtime -- user.slice AllowedCPUs=
    sudo systemctl set-property --runtime -- system.slice AllowedCPUs=
    sudo systemctl set-property --runtime -- init.scope AllowedCPUs=
}

# Define the trap to call the cleanup function
trap cleanup EXIT

mkdir -p ${SUMMARY_DIR}

echo "Disable Intel HyperThreading"
echo off | sudo tee /sys/devices/system/cpu/smt/control

echo "Enable CPU performance governor"
sudo cpupower frequency-set --governor performance

echo "Shield CPU${PROXY_CPU} and CPU${BACKEND_CPU} from the OS scheduler"
TMP=$(( PROXY_CPU > BACKEND_CPU ? PROXY_CPU : BACKEND_CPU ))
CPU_ALLOWED="0,$(( TMP + 1 ))-$(($(nproc) - 1))"

echo "System may now only use CPU: ${CPU_ALLOWED}"
sudo systemctl set-property --runtime -- user.slice AllowedCPUs=${CPU_ALLOWED}
sudo systemctl set-property --runtime -- system.slice AllowedCPUs=${CPU_ALLOWED}
sudo systemctl set-property --runtime -- init.scope AllowedCPUs=${CPU_ALLOWED}

for SIZE in ${SIZE_LIST}; do
    # this needs to be on a different NUMA node than the proxy
    CMD="PAYLOAD_SIZE=${SIZE} taskset --cpu-list 3-23 k6 run --summary-export=${SUMMARY_DIR}/stress-${PROXY}-${SIZE}B.json bench/stress.js"
    echo ${CMD}
    eval ${CMD}
done

cleanup
