#!/bin/bash

ROOT=$(dirname "$(readlink -f "$0")")
NS=ns5

sudo ip netns exec ${NS} systemd-run --scope -p Slice=proxy.slice envoy -c ${ROOT}/config.yaml --concurrency 1