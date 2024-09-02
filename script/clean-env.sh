#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

function stop_http_server {
  sudo kill -9 $(cat servers.pid)
  rm servers.pid
}

function delete_veth {
  for i in `seq 1 $1`;
  do
  	sudo ip link del veth${i} &> /dev/null
  	sudo ip netns del ns${i} &> /dev/null
  done
}

echo -e "${COLOR_YELLOW}Enable HyperThreading${COLOR_OFF}"
echo on | sudo tee /sys/devices/system/cpu/smt/control

echo -e "${COLOR_YELLOW}Disable CPU performance governor${COLOR_OFF}"
sudo cpupower frequency-set --governor ondemand

echo -e "${COLOR_YELLOW}Reset CPU shielding${COLOR_OFF}"
sudo systemctl set-property --runtime user.slice AllowedCPUs=
sudo systemctl set-property --runtime system.slice AllowedCPUs=
sudo systemctl set-property --runtime init.scope AllowedCPUs=

stop_http_server
delete_veth 4

echo -e "${COLOR_GREEN}Environment cleaned${COLOR_OFF}"

exit 0