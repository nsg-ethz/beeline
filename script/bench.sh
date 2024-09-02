#!/bin/bash

SIZE_LIST="128 256 512 1024 2048 4096 8192"
WRITE_LOG=0

# Parse arguments
while getopts "l:n:p:s:" opt; do
    case $opt in
        l ) WRITE_LOG=${OPTARG} ;;
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

ROOT=$(dirname "$(readlink -f "$0")")
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}
DIRECT=0
if [ "${PROXY}" = "none" ]; then
    echo "Running without proxy"
    DIRECT=1
fi

mkdir -p ${SUMMARY_DIR}

for SIZE in ${SIZE_LIST}; do
    LOG_OPT=""
    if [ ${WRITE_LOG} -eq 1 ]; then
        LOG_OPT="--out csv=${SUMMARY_DIR}/stress-${PROXY}-${SIZE}B-log.gz"
    fi

    CMD="k6 run -e PAYLOAD_SIZE=${SIZE} -e DIRECT=${DIRECT} --summary-export=${SUMMARY_DIR}/stress-${PROXY}-${SIZE}B.json ${LOG_OPT} bench/stress.js" 
    echo ${CMD}
    eval ${CMD}
done