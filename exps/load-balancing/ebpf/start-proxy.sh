#!/bin/bash

set -x

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

sudo taskset --cpu-list 1 ${DIR}/ebpf_proxy 0.0.0.0:3000 10.0.1.1:8000 10.0.2.1:8000 10.0.3.1:8000 10.0.4.1:8000
