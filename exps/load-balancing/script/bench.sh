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

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ $TEST_ENVOY -eq 1 ]; then
    echo "Start envoy"
    ${ROOT}/../envoy/start_proxy.sh &
    ENVOY_PID=$!

    for SIZE in 128 256 512 1024 2048; do
        ${ROOT}/k6.sh -n ${NAME} -p envoy -s ${SIZE}
    done

    echo "Kill envoy"
    kill ${ENVOY_PID}
fi

if [ $TEST_EBPF -eq 1 ]; then
    echo "Start ebpf"
    ${ROOT}/../ebpf/start_proxy.sh &
    EBPF_PID=$!

    for SIZE in 128 256 512 1024 2048; do
        ${ROOT}/k6.sh -n ${NAME} -p ebpf -s ${SIZE}
    done

    echo "Kill ebpf"
    kill ${EBPF_PID}
fi

cleanup()