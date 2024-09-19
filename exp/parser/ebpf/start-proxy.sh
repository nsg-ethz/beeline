#!/bin/bash

set -e

ROOT=$(dirname "$(readlink -f "$0")")
TARGET=${ROOT}/../../../target/release/parser-ebpf
NS=ns5

cargo b -r

RUST_LOG=debug sudo -E ${TARGET} -d "10.0.1.1:8000" --remove user-agent
