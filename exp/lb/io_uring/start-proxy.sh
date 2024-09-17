#!/bin/bash

set -e

ROOT=$(dirname "$(readlink -f "$0")")
NS=ns5

BIN=${ROOT}/../../../target/release/lb-io_uring

cargo b -r

RUST_LOG=error sudo -E ip netns exec ${NS} systemd-run --scope -p Slice=proxy.slice ${BIN} -a 0.0.0.0:3000 -b 10.0.1.1:8000 10.0.2.1:8000 10.0.3.1:8000 10.0.4.1:8000