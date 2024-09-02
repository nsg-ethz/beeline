#!/bin/bash

ROOT=$(dirname "$(readlink -f "$0")")

sudo systemd-run --scope -p Slice=proxy.slice ${ROOT}/ebpf_proxy 0.0.0.0:3000 10.0.1.1:8000 10.0.2.1:8000 10.0.3.1:8000 10.0.4.1:8000