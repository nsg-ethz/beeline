#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

# Parse arguments
while getopts "c:f:t:n:p:" opt; do
    case $opt in
        f ) FROM=${OPTARG} ;;
        t ) TO=${OPTARG} ;;
        n ) NAME=${OPTARG} ;;
        c ) PROXY_CONFIG=${OPTARG} ;;
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

for i in $(seq ${FROM} ${TO} ) ; do

    ${ROOT}/mb.sh up -c ${ROOT}/../${PROXY_CONFIG} -n ${NAME} -p ${PROXY} -e ${i}

    RATE=30000
    FILE=${SUMMARY_DIR}/${PROXY}-$(date +%s)-wrk-e${i}-${RATE}.log
    echo "epoch ${i}, rate: ${RATE}, file: ${FILE}"
    PAYLOAD_SIZE=100 BACKEND=1 wrk -d 30s -R ${RATE} -t 10 -c 100 -s wrk/rps.lua http://localhost:8080 > ${FILE}
    RET=$?

    if [ ${RET} -ne 0 ]; then
        exit $?
    fi

    ${ROOT}/mb.sh down -c ${ROOT}/../${PROXY_CONFIG} -n ${NAME} -p ${PROXY} -e ${i}

done
