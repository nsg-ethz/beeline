#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

MODULE=bpf_crypto_shash.ko
ROOT=$(dirname "$(readlink -f "$0")")
TARGET=${ROOT}/../target/release/build/${MODULE}

echo -e "${COLOR_GREEN}Compiling kernel module${COLOR_OFF}"

cd ${ROOT}/../beeline/src/bpf/crypto
make -j 4
make clean

echo -e "${COLOR_GREEN}Loading module into kernel ${COLOR_OFF}"

cd ${ROOT}
sudo rmmod ${MODULE} || true
sudo insmod ${TARGET}

sudo dmesg --since "3 seconds ago"

echo -e "${COLOR_GREEN}Done ${COLOR_OFF}"
