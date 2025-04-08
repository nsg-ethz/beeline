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
        c ) DOCKER_CONFIG=${OPTARG} ;;
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

    ssh -t moonshine "${ROOT}/sn.sh up -c ${ROOT}/../${DOCKER_CONFIG} -n ${NAME} -p ${PROXY} -e ${i}"

    REPORT=${SUMMARY_DIR}/${PROXY}-$(date +%s)-k6-e${i}-full.csv
    SUMMARY=${SUMMARY_DIR}/${PROXY}-$(date +%s)-k6-e${i}-summary.log
    k6 run ${ROOT}/../k6/compose-post.js --out csv=>(grep -e metric_name,timestamp -e http_req_duration > ${REPORT}) --summary-export ${SUMMARY}
    RET=$?

    if [ ${RET} -ne 0 ]; then
        exit $?
    fi

    ssh -t moonshine "${ROOT}/sn.sh down -c ${ROOT}/../${DOCKER_CONFIG}"

done
