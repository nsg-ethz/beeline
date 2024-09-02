#!/bin/bash

SIZE_LIST="128 256 512 1024 2048 4096 8192 16384"
WRITE_LOG=0
RATE=20000

# Parse arguments
while getopts "l:n:p:r:s:" opt; do
    case $opt in
        l ) WRITE_LOG=${OPTARG} ;;
        n ) NAME=${OPTARG} ;;
        p ) PROXY=${OPTARG} ;;
        r ) RATE=${OPTARG} ;;
        s ) SIZE_LIST=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

ROOT=$(dirname "$(readlink -f "$0")")
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}
DIRECT=0
if [ "${PROXY}" = "none" ]; then
    echo "Running without proxy"
    DIRECT=1
fi

RATE_DSC=$(numfmt --to=si ${RATE})

for SIZE in ${SIZE_LIST}; do
    LOG_OPT=""
    if [ ${WRITE_LOG} -eq 1 ]; then
        if [ -z "${PROXY}" ]; then
            echo "Error: Specify the proxy name with the -p option";
            exit 1
        fi
        LOG_OPT="--out csv=${SUMMARY_DIR}/stress@${RATE_DSC}-${PROXY}-${SIZE}B-log.gz"
    fi

    SUM_OPT=""
    if [ -n "${NAME}" ]; then
        if [ -z "${PROXY}" ]; then
                echo "Error: Specify the proxy name with the -p option";
                exit 1
        fi
        mkdir -p ${SUMMARY_DIR}
        SUM_OPT="--summary-export=${SUMMARY_DIR}/stress@${RATE_DSC}-${PROXY}-${SIZE}B.json"
    fi

    # echo "Warming up..."
    # WARMUP_CMD="k6 run -q --no-summary -e RATE=${RATE} -e PAYLOAD_SIZE=${SIZE} -e DIRECT=${DIRECT} bench/warmup.js" 
    # eval ${WARMUP_CMD}

    BENCH_CMD="k6 run -e RATE=${RATE} -e PAYLOAD_SIZE=${SIZE} -e DIRECT=${DIRECT} ${SUM_OPT} ${LOG_OPT} bench/latency.js" 
    echo ${BENCH_CMD}
    eval ${BENCH_CMD}
done