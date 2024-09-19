#!/bin/bash

SIZE_LIST="128 256 512 1024 2048 4096 8192"
WRITE_LOG=0
RATE=20000
DIRECT=0

# Parse arguments
while getopts "dln:p:r:s:u:" opt; do
    case $opt in
        d ) DIRECT=1 ;;
        l ) WRITE_LOG=1 ;;
        n ) NAME=${OPTARG} ;;
        p ) PROXY=${OPTARG} ;;
        r ) RATE=${OPTARG} ;;
        s ) SIZE_LIST=${OPTARG} ;;
        u ) VUS=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

shift $(($OPTIND-1))
SCRIPT="$1"

if [ -z "${SCRIPT}" ]; then
    SCRIPT="rps.js"
fi
if [[ $SCRIPT != *.js ]]; then
    SCRIPT="${SCRIPT}.js"
fi

ROOT=$(dirname "$(readlink -f "$0")")
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}

for SIZE in ${SIZE_LIST}; do
    LOG_OPT=""
    if [ ${WRITE_LOG} -eq 1 ]; then
        if [ -z "${PROXY}" ]; then
            echo "Error: Specify the proxy name with the -p option";
            exit 1
        fi
        FILE=${SCRIPT%%.*}
        LOG_OPT="--out csv=${SUMMARY_DIR}/${FILE}-${PROXY}-${SIZE}B-log.gz"
    fi

    SUM_OPT=""
    if [ -n "${NAME}" ]; then
        if [ -z "${PROXY}" ]; then
                echo "Error: Specify the proxy name with the -p option";
                exit 1
        fi
        mkdir -p ${SUMMARY_DIR}
        FILE=${SCRIPT%%.*}
        SUM_OPT="--summary-export=${SUMMARY_DIR}/${FILE}-${PROXY}-${SIZE}B.json"
    fi

    BENCH_CMD="k6 run --summary-trend-stats \"min,avg,med,max,p(70),p(75),p(80),p(85),p(90),p(95),p(99)\" -e VUS=${VUS} -e RATE=${RATE} -e PAYLOAD_SIZE=${SIZE} -e DIRECT=${DIRECT} ${SUM_OPT} ${LOG_OPT} k6/${SCRIPT}" 
    echo ${BENCH_CMD}
    eval ${BENCH_CMD}
done