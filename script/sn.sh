#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

ITERS=1

# Parse arguments
while getopts "d:i:n:p:" opt; do
    case $opt in
        i ) ITERS=${OPTARG} ;;
        n ) NAME=${OPTARG} ;;
        d ) DOCKER_EXP=${OPTARG} ;;
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

trap stop_experiment INT

for i in {i..${ITERS}} ; do
    for j in {1..52} ; do
        RATE=$(( i * 50 ))
        FILE=${SUMMARY_DIR}/${PROXY}-$(date +%s)-wrk-e${i}-${RATE}.log
        BENCH_CMD="wrk -t 10 -c 100 -d 5s -L -s ${SOCIAL_NETWORK_DIR}/wrk2/scripts/social-network/compose-post.lua http://moonshine:8080/wrk2-api/post/compose -R ${RATE} > ${FILE}"
        echo ${BENCH_CMD}
        eval ${BENCH_CMD}
        RET=$?

        if [ ${RET} -ne 0 ]; then
            exit $?
        fi
    done
done

kill ${CPU_PID} 2>&1 >/dev/null
