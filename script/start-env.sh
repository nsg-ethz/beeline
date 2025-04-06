#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

IFACE="eno1"
ROOT=$(dirname "$(readlink -f "$0")")

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
    sudo ip addr add 10.0.${i}.1/24 dev veth${i}
    sudo ip link set dev veth${i} up

    # add route so ns can reach each other
    sudo ip -netns ns${i} route add default via 10.0.${i}.1 dev veth${i}_

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

/bin/bash ${ROOT}/clean-env.sh

echo -e "${COLOR_YELLOW}Update system settings${COLOR_OFF}"
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w fs.file-max=1000000

echo -e "${COLOR_YELLOW}Creating namespaces${COLOR_OFF}"
create_veth 5
echo -e "${COLOR_GREEN}Namespaces created${COLOR_OFF}"

echo -e "${COLOR_YELLOW}Let's check if everything is setup correctly${COLOR_OFF}"
ping_cycle 5

echo -e "${COLOR_GREEN}Done${COLOR_OFF}"
