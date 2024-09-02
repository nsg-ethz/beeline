#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

ADDRESS="127.0.0.1:3000"
PROXY="naive"
NUM_SERVERS="4"
DURATION="5"
RES_DIR="res"

show_help() {
cat << EOF
Stress Test with fortio.

Usage: ./bench.sh [-a ADDRESS] [-n SERVERS] [-t DURATION]

Params:
  -a  address to be tested.
      Defaults to 127.0.0.1:3000

  -n  number of servers.
      Defaults to 4

  -p  reverse proxy type.
      Must be one of envoy, naive, or ebpf.
      Defaults to naive.

  -t duration.
     Defaults to 5.

  -h  show this help text

Example:
  $ ./bench.sh -n 4 -t 10
EOF
}

### CLI

while getopts ":a:n:t:Hh" opt; do
  case $opt in
    a)
      ADDRESS=$OPTARG
      ;;
    n)
      NUM_SERVERS=$OPTARG
      ;;
    p)
      PROXY=$OPTARG
      ;;
    t)
      DURATION=$OPTARG
      ;;
    h)
      show_help
      exit 0
      ;;
    \?)
      show_help >&2
      echo "Invalid argument: $OPTARG" &2
      exit 1
      ;;
  esac
done

shift $((OPTIND-1))

### MAIN

./start-env.sh

echo -e "${COLOR_YELLOW}Starting proxy...${COLOR_OFF}"
cd ${PROXY}
./start-proxy.sh > /dev/null &
PROXY_PID=$!
cd ..

echo -e "${COLOR_YELLOW}Starting stress test...${COLOR_OFF}"
sleep 1

fortio load -json ${RES_DIR}/${PROXY}.json -n 1000 ${ADDRESS}/server1

pkill -TERM -P ${PROXY_PID}

./clean-env.sh