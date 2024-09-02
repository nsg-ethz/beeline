#!/bin/bash

ROOT=$(dirname "$(readlink -f "$0")")

sudo systemd-run --scope -p Slice=proxy.slice envoy -c ${ROOT}/config.yaml --concurrency 1