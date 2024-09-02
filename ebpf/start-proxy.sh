#!/bin/bash

ROOT=$(dirname "$(readlink -f "$0")")

if [ -z ${PROXY_CPU} ]; then
    echo "Error: PROXY_CPU is not set"
    exit 1
fi

sudo taskset --cpu-list ${PROXY_CPU} ${ROOT}/ebpf_proxy 0.0.0.0:3000 10.0.1.1:8000 10.0.2.1:8000 10.0.3.1:8000 10.0.4.1:8000
