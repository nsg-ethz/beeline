#!/bin/bash

while getopts "n:p:s:" opt
do
   case "$opt" in
      n ) NAME=${OPTARG} ;;
      p ) PROXY=${OPTARG} ;;
      s ) SIZE=${OPTARG} ;;
   esac
done

if [ -z ${PROXY} ] || [ -z ${SIZE} ]
then
   echo "Some or all of the parameters are empty";
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}

mkdir -p ${SUMMARY_DIR}

# this needs to be on a different NUMA node than the proxy
CMD="PAYLOAD_SIZE=${SIZE} taskset --cpu-list 2-47 k6 run --summary-export=${SUMMARY_DIR}/stress-${PROXY}-${SIZE}B.json bench/stress.js"
echo ${CMD}
eval ${CMD}
