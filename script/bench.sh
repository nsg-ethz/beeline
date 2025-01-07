#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

SIZE_LIST="128 256 512 1024 2048 4096 8192"
WRITE_LOG=0
RATE=20000
DIRECT=0

ROOT=$(dirname "$(readlink -f "$0")")

function stop_experiment {
    sudo systemctl stop exp-pod5-proxy.scope > /dev/null 2>&1
}

trap stop_experiment INT

# Parse arguments
while getopts "dln:p:r:s:u:" opt; do
    case $opt in
        d ) DIRECT=1 ;;
        l ) WRITE_LOG=1 ;;
        n ) NAME=${OPTARG} ;;
        p ) PROXY=${OPTARG} ;;
        r ) RATE=${OPTARG} ;;
        s ) SIZE_LIST=${OPTARG} ;;
        u ) VUS=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

PROXY_BIN=${ROOT}/../target/release/${PROXY}

cargo b -r --bin ${PROXY}

stop_experiment

sudo -b -E systemd-run -q --scope -u exp-pod5-proxy --slice pod5.slice ${PROXY_BIN} -a 127.0.0.1:3000 -c ${ROOT}/../config/bench.yaml
echo -e "${COLOR_GREEN}Launched exp-pod5-proxy in pod5.${COLOR_OFF}"

sleep 0.25

shift $(($OPTIND-1))
SCRIPT="$1"

if [ -z "${SCRIPT}" ]; then
    SCRIPT="rps.js"
fi
if [[ $SCRIPT != *.js ]]; then
    SCRIPT="${SCRIPT}.js"
fi

ROOT=$(dirname "$(readlink -f "$0")")
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}

for SIZE in ${SIZE_LIST}; do
    LOG_OPT=""
    if [ ${WRITE_LOG} -eq 1 ]; then
        if [ -z "${PROXY}" ]; then
            echo "Error: Specify the proxy name with the -p option";
            exit 1
        fi
        FILE=${SCRIPT%%.*}
        LOG_OPT="--out csv=${SUMMARY_DIR}/${FILE}-${PROXY}-${SIZE}B-log.gz"
    fi

    SUM_OPT=""
    if [ -n "${NAME}" ]; then
        if [ -z "${PROXY}" ]; then
                echo "Error: Specify the proxy name with the -p option";
                exit 1
        fi
        mkdir -p ${SUMMARY_DIR}
        FILE=${SCRIPT%%.*}
        SUM_OPT="--summary-export=${SUMMARY_DIR}/${FILE}-${PROXY}-${SIZE}B.json"
    fi

    BENCH_CMD="k6 run -e VUS=${VUS} -e RATE=${RATE} -e PAYLOAD_SIZE=${SIZE} -e DIRECT=${DIRECT} ${SUM_OPT} ${LOG_OPT} k6/${SCRIPT}"
    echo ${BENCH_CMD}
    eval ${BENCH_CMD}
    RET=$?

    sudo chown -R ${USER}:"domain users" ${SUMMARY_DIR}

    if [ ${RET} -ne 0 ]; then
        exit $?
    fi
done

stop_experiment
