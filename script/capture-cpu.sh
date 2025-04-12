#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

ROOT=$(dirname "$(readlink -f "$0")")

# Parse arguments
while getopts "n:p:e:" opt; do
    case $opt in
        n ) NAME=${OPTARG} ;;
        p ) PROXY=${OPTARG} ;;
        e ) EPOCH=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

ROOT=$(dirname "$(readlink -f "$0")")
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}/${PROXY}-cpu-e${EPOCH}
SOCIAL_NETWORK_DIR=${ROOT}/../social_network

rm -rf ${SUMMARY_DIR} >/dev/null 2>&1
mkdir -p ${SUMMARY_DIR}

function read_cpu_usage() {
    awk '$1 == "usage_usec" { print $2 }' /sys/fs/cgroup/beeline.slice/cpu.stat
}

TS=$(date +%s%N)
CPU=$(read_cpu_usage)

while sleep 1; do
    FILE=${SUMMARY_DIR}/$(date +%s).log

    TS_NEW=$(date +%s%N)
    CPU_NEW=$(read_cpu_usage)

    RES=$(bc -l <<< "(${CPU_NEW} - ${CPU}) / (${TS_NEW} - ${TS}) * 1000")
    echo ${RES} > ${FILE}

    TS=${TS_NEW}
    CPU=${CPU_NEW}
done
