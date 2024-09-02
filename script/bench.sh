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
   echo "Error: Some or all of the parameters are empty";
   exit 1
fi

ROOT=$(dirname "$(readlink -f "$0")")
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}

mkdir -p ${SUMMARY_DIR}

for SIZE in ${SIZE_LIST}; do
    CMD="k6 run -e PAYLOAD_SIZE=${SIZE} --summary-export=${SUMMARY_DIR}/stress-${PROXY}-${SIZE}B.json bench/stress.js"
    echo ${CMD}
    eval ${CMD}
done