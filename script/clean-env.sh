#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

function stop_experiment {
    sudo systemctl list-unit-files | grep exp-pod | awk '{print $1}' | sudo xargs -L 1 systemctl stop > /dev/null 2>&1
}

function delete_veth {
  for i in `seq 1 $1`;
  do
  	sudo ip link del veth${i} &> /dev/null
  	sudo ip netns del ns${i} &> /dev/null
  done
}

echo -e "${COLOR_YELLOW}Stopping services${COLOR_OFF}"
stop_experiment

echo -e "${COLOR_YELLOW}Delete virtual network${COLOR_OFF}"
delete_veth 5

echo -e "${COLOR_YELLOW}Enable HyperThreading${COLOR_OFF}"
echo on | sudo tee /sys/devices/system/cpu/smt/control

echo -e "${COLOR_YELLOW}Disable CPU performance governor${COLOR_OFF}"
sudo cpupower frequency-set --governor ondemand

echo -e "${COLOR_YELLOW}Reset CPU shielding${COLOR_OFF}"
CPU_ALLOWED="0-47"
sudo systemctl set-property --runtime user.slice AllowedCPUs=${CPU_ALLOWED}
sudo systemctl set-property --runtime system.slice AllowedCPUs=${CPU_ALLOWED}
sudo systemctl set-property --runtime init.scope AllowedCPUs=${CPU_ALLOWED}

if [ $(nproc) -ne  48 ]; then
  echo -e "${COLOR_RED}Failed to reset all CPUs${COLOR_OFF}"
fi

echo -e "${COLOR_GREEN}Environment cleaned${COLOR_OFF}"
