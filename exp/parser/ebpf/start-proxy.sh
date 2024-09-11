#!/bin/bash

ROOT=$(dirname "$(readlink -f "$0")")
TARGET=${ROOT}/../../../target/release/parser-ebpf
NS=ns5

cargo b -r

# sudo ip netns exec ${NS} systemd-run --scope -p Slice=proxy.slice ${TARGET} -p 8000
RUST_LOG=debug sudo -E ${TARGET} -p 8000