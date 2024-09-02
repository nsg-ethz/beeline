#!/bin/bash

cleanup() {
    # Add your cleanup code here
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

TEST_EBPF=0
TEST_ENVOY=0

# Parse arguments
while getopts ":n:p:" opt; do
    case $opt in
        n ) NAME=${OPTARG} ;;
        p)
            case $OPTARG in
                envoy)
                    TEST_ENVOY=1
                    ;;
                ebpf)
                    TEST_EBPF=1
                    ;;
                *)
                    echo "Invalid argument: $OPTARG"
                    ;;
            esac
            ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

echo "Enable CPU performance governor"
sudo cpupower frequency-set --governor performance

ROOT=$(dirname "$(readlink -f "$0")")

if [ $TEST_ENVOY -eq 1 ]; then
    for SIZE in 128 256 512 1024 2048 4096 8192; do
        ${ROOT}/k6.sh -n ${NAME} -p envoy -s ${SIZE}
    done
fi

if [ $TEST_EBPF -eq 1 ]; then

    for SIZE in 128 256 512 1024 2048 4096 8192; do
        ${ROOT}/k6.sh -n ${NAME} -p ebpf -s ${SIZE}
    done
fi

cleanup
