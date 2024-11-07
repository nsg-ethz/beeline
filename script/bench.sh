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
ECHO_BIN=${ROOT}/../target/release/echo
PROXY_BIN=${ROOT}/../target/release/proxy

function stop_experiment {
    systemctl list-unit-files | grep exp-pod | awk '{print $1}' | xargs -L 1 sudo systemctl stop > /dev/null 2>&1
}

function pod {
    local UNIT_NAME="exp-pod${1}-$(basename ${2})"
    sudo -b -E ip netns exec ns${1} systemd-run -q --scope -u ${UNIT_NAME} --slice pod${1}.slice "${@:2}"
    echo -e "${COLOR_GREEN}Launched ${UNIT_NAME} in pod${1}.${COLOR_OFF}"
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

cargo b -r --bin echo
cargo b -r --bin proxy

stop_experiment

echo -e "${COLOR_GREEN}Preparing environment${COLOR_OFF}"

pod 1 ${ECHO_BIN} -a 10.0.1.1:8000 -H "signature: server1" -e "conn-id"
pod 2 ${ECHO_BIN} -a 10.0.2.1:8000 -H "signature: server2" -e "conn-id"
pod 3 ${ECHO_BIN} -a 10.0.3.1:8000 -H "signature: server3" -e "conn-id"
pod 4 ${ECHO_BIN} -a 10.0.4.1:8000 -H "signature: server4" -e "conn-id"

sudo -b -E systemd-run -q --scope -u exp-pod5-proxy ${PROXY_BIN} -c ${ROOT}/../config/bench.yaml
echo -e "${COLOR_GREEN}Launched exp-pod5-proxy in pod5.${COLOR_OFF}"

sleep 0.25
systemctl list-unit-files | grep exp-pod | awk '{print $1}'

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