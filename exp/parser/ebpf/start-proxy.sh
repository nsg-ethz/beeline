#!/bin/bash

set -e

ROOT=$(dirname "$(readlink -f "$0")")
TARGET=${ROOT}/../../../target/release/parser-ebpf
NS=ns5

cargo b -r

sudo -E ip netns exec ${NS} systemd-run --scope -p Slice=proxy.slice ${TARGET} -a "10.0.5.1:3000" -d "10.0.1.1:8000" --remove user-agent