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

DEST_HOST="moonshine"
ROOT=$(dirname "$(readlink -f "$0")")
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}
SOCIAL_NETWORK_DIR=${ROOT}/../test/social_network

mkdir -p ${SUMMARY_DIR}

for i in $(seq ${FROM} ${TO} ) ; do

    REPORT=${SUMMARY_DIR}/${PROXY}-k6-e${i}-full.csv
    SUMMARY=${SUMMARY_DIR}/${PROXY}-k6-e${i}-summary.json

    case ${BENCH} in
        sm)
            ssh -t ${DEST_HOST} "source ~/.profile && ${ENV} ${ROOT}/sm.sh up -c ${ROOT}/../${CONFIG} -n ${NAME} -p ${PROXY} -e ${i}"
            echo -e "${COLOR_YELLOW}Starting epoch ${i}, summary: ${SUMMARY}${COLOR_OFF}"

            if [ "${WRITE_REPORT}" = true ]; then
                k6 run ${SCRIPT} --out csv=>(grep -e metric_name,timestamp -e http_req_duration > ${REPORT}) --summary-export ${SUMMARY}
            else
                k6 run ${SCRIPT} --summary-export ${SUMMARY}
            fi

            ssh -t ${DEST_HOST} "source ~/.profile && ${ENV} ${ROOT}/sm.sh down -c ${ROOT}/../${CONFIG} -n ${NAME} -p ${PROXY} -e ${i}"
            ;;

        mb)
            ${ROOT}/mb.sh up -c ${ROOT}/../${CONFIG} -n ${NAME} -p ${PROXY} -e ${i} -m
            echo -e "${COLOR_YELLOW}Starting epoch ${i}, summary: ${SUMMARY}${COLOR_OFF}"

            if [ "${WRITE_REPORT}" = true ]; then
                k6 run ${SCRIPT} -e PAYLOAD_SIZE=100 -e RATE=10000 -e URL=http://localhost:8080 --out csv=>(grep -e metric_name,timestamp -e http_req_duration > ${REPORT}) --summary-export ${SUMMARY}
            else
                k6 run ${SCRIPT} -e PAYLOAD_SIZE=100 -e RATE=10000 -e URL=http://localhost:8080 --summary-export ${SUMMARY}
            fi

            ${ROOT}/mb.sh down -c ${ROOT}/../${CONFIG} -n ${NAME} -p ${PROXY} -e ${i} -m
            ;;

    esac

done
