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

DEST_HOST=${DEST_HOST:-$(hostname)}
ROOT=$(dirname "$(readlink -f "$0")")
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}
SOCIAL_NETWORK_DIR=${ROOT}/../test/social_network

mkdir -p ${SUMMARY_DIR}

if [ "${BENCH}" = sm ]; then
    : "${LOAD_GEN_HOST:?LOAD_GEN_HOST must name the host that runs k6}"
    # ufw only accepts addresses, not host names
    LOAD_GEN_IP=$(getent ahostsv4 ${LOAD_GEN_HOST} | awk '{ print $1; exit }')
    : "${LOAD_GEN_IP:?cannot resolve ${LOAD_GEN_HOST}}"
    UFW_RULE="from ${LOAD_GEN_IP} to any port 9991 proto tcp"
    # the containers reach the proxy on the host
    DOCKER_RULE="from 172.18.0.0/24"
    sudo ufw allow ${UFW_RULE}
    sudo ufw allow ${DOCKER_RULE}
    trap "sudo ufw delete allow ${UFW_RULE}; sudo ufw delete allow ${DOCKER_RULE}" EXIT

    # upload the whole script directory, the scripts import their siblings
    REMOTE_DIR=$(ssh ${LOAD_GEN_HOST} mktemp -d)
    : "${REMOTE_DIR:?cannot create a temporary directory on ${LOAD_GEN_HOST}}"
    trap "sudo ufw delete allow ${UFW_RULE}; sudo ufw delete allow ${DOCKER_RULE}; ssh ${LOAD_GEN_HOST} rm -rf ${REMOTE_DIR}" EXIT
    scp -rq "$(dirname "${SCRIPT}")" ${LOAD_GEN_HOST}:${REMOTE_DIR}/k6 || exit 1
fi

for i in $(seq ${FROM} ${TO} ) ; do

    REPORT=${SUMMARY_DIR}/${PROXY}-k6-e${i}-full.csv
    SUMMARY=${SUMMARY_DIR}/${PROXY}-k6-e${i}-summary.json

    case ${BENCH} in
        sm)
            env ${ENV} ${ROOT}/sm.sh up -c ${CONFIG} -n ${NAME} -p ${PROXY} -e ${i}
            echo -e "${COLOR_YELLOW}Starting epoch ${i} from ${LOAD_GEN_HOST}, summary: ${SUMMARY}${COLOR_OFF}"

            K6_ARGS="-e DEST_HOST=${DEST_HOST} --summary-export ${REMOTE_DIR}/$(basename ${SUMMARY})"
            if [ "${WRITE_REPORT}" = true ]; then
                K6_ARGS+=" --out csv=>(grep -e metric_name,timestamp -e http_req_duration > ${REMOTE_DIR}/$(basename ${REPORT}))"
            fi

            ${ROOT}/capture-cpu.sh -n ${NAME} -p ${PROXY} -e ${i} &
            CPU_PID=$!
            ssh -t ${LOAD_GEN_HOST} "source ~/.profile && cd ${REMOTE_DIR}/k6 && k6 run $(basename ${SCRIPT}) ${K6_ARGS}"
            kill ${CPU_PID}
            scp -q "${LOAD_GEN_HOST}:${REMOTE_DIR}/${PROXY}-k6-e${i}-*" ${SUMMARY_DIR}/

            env ${ENV} ${ROOT}/sm.sh down -c ${CONFIG} -n ${NAME} -p ${PROXY} -e ${i}
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
