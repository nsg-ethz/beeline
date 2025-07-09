#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

BENCH=$1
shift 1

WRITE_REPORT=false

# Parse arguments
while getopts "c:e:f:t:n:p:rs:" opt; do
    case $opt in
        e ) ENV=${OPTARG} ;;
        f ) FROM=${OPTARG} ;;
        t ) TO=${OPTARG} ;;
        n ) NAME=${OPTARG} ;;
        c ) CONFIG=${OPTARG} ;;
        p ) PROXY=${OPTARG} ;;
        r ) WRITE_REPORT=true ;;
        s ) SCRIPT=${OPTARG} ;;

        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

ROOT=$(dirname "$(readlink -f "$0")")
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}
SOCIAL_NETWORK_DIR=${ROOT}/../test/social_network

mkdir -p ${SUMMARY_DIR}

for i in $(seq ${FROM} ${TO} ) ; do

    REPORT=${SUMMARY_DIR}/${PROXY}-k6-e${i}-full.csv
    SUMMARY=${SUMMARY_DIR}/${PROXY}-k6-e${i}-summary.json

    case ${BENCH} in
        sm)
            ssh -t moonshine "source ~/.profile && ${ENV} ${ROOT}/sm.sh up -c ${ROOT}/../${CONFIG} -n ${NAME} -p ${PROXY} -e ${i}"
            echo -e "${COLOR_YELLOW}Starting epoch ${i}, summary: ${SUMMARY}${COLOR_OFF}"

            if [[ "${CONFIG}" == *sn* ]]; then
                K6_SCRIPT=${ROOT}/../k6/sn-compose-post.js
            elif [[ "${CONFIG}" == *ms* ]]; then
                K6_SCRIPT=${ROOT}/../k6/ms-compose-review.js
            elif [[ "${CONFIG}" == *ssm* ]]; then
                K6_SCRIPT="${ROOT}/../${SCRIPT} -e PAYLOAD_SIZE=100 -e RATE=5000  -e URL=http://moonshine:8080"
            fi

            if [ "${WRITE_REPORT}" = true ]; then
                k6 run ${K6_SCRIPT} --no-thresholds --out csv=>(grep -e metric_name,timestamp -e http_req_duration > ${REPORT}) --summary-export ${SUMMARY}
            else:
                k6 run ${K6_SCRIPT} --no-thresholds --summary-export ${SUMMARY}
            fi

            ssh -t moonshine "source ~/.profile && ${ENV} ${ROOT}/sm.sh down -c ${ROOT}/../${CONFIG} -n ${NAME} -p ${PROXY} -e ${i}"
            ;;

        mb)
            ${ROOT}/mb.sh up -c ${ROOT}/../${CONFIG} -n ${NAME} -p ${PROXY} -e ${i} -m
            echo -e "${COLOR_YELLOW}Starting epoch ${i}, summary: ${SUMMARY}${COLOR_OFF}"

            if [ "${WRITE_REPORT}" = true ]; then
                k6 run ${K6_SCRIPT} -e PAYLOAD_SIZE=100 -e RATE=10000 -e URL=http://localhost:8080 --no-thresholds --out csv=>(grep -e metric_name,timestamp -e http_req_duration > ${REPORT}) --summary-export ${SUMMARY}
            else:
                k6 run ${K6_SCRIPT} -e PAYLOAD_SIZE=100 -e RATE=10000 -e URL=http://localhost:8080 --no-thresholds --summary-export ${SUMMARY}
            fi

            ${ROOT}/mb.sh down -c ${ROOT}/../${CONFIG} -n ${NAME} -p ${PROXY} -e ${i} -m
            ;;

    esac

done
