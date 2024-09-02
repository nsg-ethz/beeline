#!/bin/bash

ROOT=$(dirname "$(readlink -f "$0")")

if [ -z ${PROXY_CPU} ]; then
    echo "Error: PROXY_CPU is not set"
    exit 1
fi

taskset --cpu-list ${PROXY_CPU} envoy -c ${ROOT}/config.yaml --concurrency 1