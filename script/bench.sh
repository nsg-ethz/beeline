#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

BENCH=$1
shift 1

# Parse arguments
while getopts "c:f:t:n:p:" opt; do
    case $opt in
        f ) FROM=${OPTARG} ;;
        t ) TO=${OPTARG} ;;
        n ) NAME=${OPTARG} ;;
        c ) CONFIG=${OPTARG} ;;
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

    case ${BENCH} in
        sn)
            ssh -t moonshine "${ROOT}/sn.sh up -c ${ROOT}/../${CONFIG} -n ${NAME} -p ${PROXY} -e ${i}"

            REPORT=${SUMMARY_DIR}/${PROXY}-k6-e${i}-full.csv
            SUMMARY=${SUMMARY_DIR}/${PROXY}-k6-e${i}-summary.log
            echo -e "${COLOR_YELLOW}Starting epoch ${i}, summary: ${SUMMARY}${COLOR_OFF}"

            k6 run ${ROOT}/../k6/compose-post.js --no-thresholds --out csv=>(grep -e metric_name,timestamp -e http_req_duration > ${REPORT}) --summary-export ${SUMMARY}

            ssh -t moonshine "${ROOT}/sn.sh down -c ${ROOT}/../${CONFIG}"
            ;;

        mb)
            ${ROOT}/mb.sh up -c ${ROOT}/../${CONFIG} -n ${NAME} -p ${PROXY} -e ${i}

            SUMMARY=${SUMMARY_DIR}/${PROXY}-wrk-e${i}-summary.log
            echo -e "${COLOR_YELLOW}Starting epoch ${i}, summary: ${SUMMARY}${COLOR_OFF}"

            PAYLOAD_SIZE=100 BACKEND=1 sudo -E systemd-run -q --scope -u mb-wrk --slice beeline.slice wrk -L -d 120s -R 30000 -t 10 -c 100 -s wrk/rps.lua http://localhost:8080 > ${SUMMARY}

            ${ROOT}/mb.sh down -c ${ROOT}/../${CONFIG} -n ${NAME} -p ${PROXY} -e ${i}
            ;;

    esac

done
