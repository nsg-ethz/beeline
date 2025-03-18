#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

RATE_LIST="200 400 600 800 1000 1200 1400 1600 1800 2000 2200 2400 2600 2800 3000"
ROOT=$(dirname "$(readlink -f "$0")")

# Parse arguments
while getopts "dln:p:r:s:u:" opt; do
    case $opt in
        n ) NAME=${OPTARG} ;;
        p ) PROXY=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

ROOT=$(dirname "$(readlink -f "$0")")
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}
SOCIAL_NETWORK_DIR=${ROOT}/../social_network

mkdir -p ${SUMMARY_DIR}

for RATE in ${RATE_LIST}; do
    FILE=${SUMMARY_DIR}/${PROXY}-${RATE}.log
    BENCH_CMD="taskset --cpu-list 24-31 wrk -t 10 -c 100 -d 30s -L -s ${SOCIAL_NETWORK_DIR}/wrk2/scripts/social-network/compose-post.lua http://localhost:8080/wrk2-api/post/compose -R ${RATE} > ${FILE}"
    echo ${BENCH_CMD}
    eval ${BENCH_CMD}
    RET=$?

    if [ ${RET} -ne 0 ]; then
        exit $?
    fi
done
