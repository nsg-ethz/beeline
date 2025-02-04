#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

IFACE="enp1s0"
ROOT=$(dirname "$(readlink -f "$0")")
ECHO_BIN=${ROOT}/../target/release/echo

function create_veth {
  sudo iptables -P FORWARD ACCEPT
  for i in `seq 1 $1`;
  do
  	sudo ip netns add ns${i}
  	sudo ip link add veth${i}_ type veth peer name veth${i}
  	sudo ip link set veth${i}_ netns ns${i}

    # setup ns interfaces
    sudo ip -netns ns${i} link set dev lo up
    sudo ip -netns ns${i} link set dev veth${i}_ promisc on
    sudo ip -netns ns${i} addr add 10.0.${i}.1/24 dev veth${i}_
    sudo ip -netns ns${i} link set dev veth${i}_ up

    # setup local interfaces
    sudo ip addr add 10.0.${i}.254/24 dev veth${i}
    sudo ip link set dev veth${i} up

    # add route so ns can reach each other
    sudo ip -netns ns${i} route add default via 10.0.${i}.254 dev veth${i}_

    echo -e "${COLOR_GREEN}Namespace ns${i} created${COLOR_OFF}"

    sudo iptables -t nat -A POSTROUTING -s 10.0.${i}.1/255.255.255.0 -o ${IFACE} -j MASQUERADE
    sudo iptables -A FORWARD -i ${IFACE} -o veth${i} -j ACCEPT
    sudo iptables -A FORWARD -o ${IFACE} -i veth${i} -j ACCEPT
  done

  echo -e "${COLOR_GREEN}Configuring ns5...${COLOR_OFF}"
  sudo mkdir -p /etc/netns/ns5
  echo "nameserver 8.8.8.8" | sudo tee /etc/netns/ns5/resolv.conf
  echo "127.0.0.1 localhost" | sudo tee /etc/netns/ns5/hosts
}

function ping_cycle {
  for i in `seq 1 $1`;
  do
    for j in `seq 1 $1`;
    do
      if [ "$i" -ne "$j" ]; then
        sudo ip netns exec ns$i ping 10.0.$j.1 -c 2 -i 0.1
      fi
    done
  done
}

function pod {
    local UNIT_NAME="exp-pod${1}-$(basename ${2})-$(uuidgen)"
    sudo -b -E ip netns exec ns${1} systemd-run -q --scope -u ${UNIT_NAME} --slice pod${1}.slice "${@:2}"
    echo -e "${COLOR_GREEN}Launched ${UNIT_NAME} in pod${1}.${COLOR_OFF}"
}

/bin/bash ${ROOT}/clean-env.sh

echo -e "${COLOR_YELLOW}Update system settings${COLOR_OFF}"
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w fs.file-max=1000000

echo -e "${COLOR_YELLOW}Creating namespaces${COLOR_OFF}"
create_veth 5
echo -e "${COLOR_GREEN}Namespaces created${COLOR_OFF}"

echo -e "${COLOR_YELLOW}Disable HyperThreading${COLOR_OFF}"
echo off | sudo tee /sys/devices/system/cpu/smt/control

echo -e "${COLOR_YELLOW}Enable CPU performance governor${COLOR_OFF}"
sudo cpupower frequency-set --governor performance

echo -e "${COLOR_YELLOW}Shield CPUs from the OS scheduler${COLOR_OFF}"
CPU_ALLOWED="0,10-47"

echo -e "${COLOR_YELLOW}System may now only use CPU: ${CPU_ALLOWED}${COLOR_OFF}"
sudo systemctl set-property --runtime user.slice AllowedCPUs=${CPU_ALLOWED}
sudo systemctl set-property --runtime system.slice AllowedCPUs=${CPU_ALLOWED}
sudo systemctl set-property --runtime init.scope AllowedCPUs=${CPU_ALLOWED}
sudo systemctl set-property --runtime pod1.slice AllowedCPUs=1,2
sudo systemctl set-property --runtime pod2.slice AllowedCPUs=3,4
sudo systemctl set-property --runtime pod3.slice AllowedCPUs=5,6
sudo systemctl set-property --runtime pod4.slice AllowedCPUs=7,8
sudo systemctl set-property --runtime pod5.slice AllowedCPUs=9,10

echo -e "${COLOR_GREEN}CPUs prepared for performance testing...\n${COLOR_OFF}"

echo -e "${COLOR_YELLOW}Let's check if everything is setup correctly${COLOR_OFF}"
ping_cycle 5

cargo b -r --bin echo

echo -e "${COLOR_YELLOW}Starting services${COLOR_OFF}"

pod 1 ${ECHO_BIN} -a 10.0.1.1:8001 -H "signature: server1" -e "conn-id"
pod 1 ${ECHO_BIN} -a 10.0.1.1:8002 -H "signature: server1" -e "conn-id"
pod 1 ${ECHO_BIN} -a 10.0.1.1:8003 -H "signature: server1" -e "conn-id"
pod 1 ${ECHO_BIN} -a 10.0.1.1:8004 -H "signature: server1" -e "conn-id"

pod 2 ${ECHO_BIN} -a 10.0.2.1:8001 -H "signature: server2" -e "conn-id"
pod 2 ${ECHO_BIN} -a 10.0.2.1:8002 -H "signature: server2" -e "conn-id"
pod 2 ${ECHO_BIN} -a 10.0.2.1:8003 -H "signature: server2" -e "conn-id"
pod 2 ${ECHO_BIN} -a 10.0.2.1:8004 -H "signature: server2" -e "conn-id"

pod 3 ${ECHO_BIN} -a 10.0.3.1:8001 -H "signature: server3" -e "conn-id"
pod 3 ${ECHO_BIN} -a 10.0.3.1:8002 -H "signature: server3" -e "conn-id"
pod 3 ${ECHO_BIN} -a 10.0.3.1:8003 -H "signature: server3" -e "conn-id"
pod 3 ${ECHO_BIN} -a 10.0.3.1:8004 -H "signature: server3" -e "conn-id"

pod 4 ${ECHO_BIN} -a 10.0.4.1:8001 -H "signature: server4" -e "conn-id"
pod 4 ${ECHO_BIN} -a 10.0.4.1:8002 -H "signature: server4" -e "conn-id"
pod 4 ${ECHO_BIN} -a 10.0.4.1:8003 -H "signature: server4" -e "conn-id"
pod 4 ${ECHO_BIN} -a 10.0.4.1:8004 -H "signature: server4" -e "conn-id"

echo -e "${COLOR_GREEN}Done${COLOR_OFF}"
