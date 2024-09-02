#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

function start_http_server {
  rm -f servers.pid
  for i in `seq 1 $1`;
  do
  	sudo ip netns exec ns${i} sudo python3 http_server.py -a 10.0.${i}.1 -p 8000 -n server${i} > /dev/null 2>&1 &
    echo $! >> servers.pid
    echo -e "${COLOR_GREEN}Server server${i} in ns${i} started.${COLOR_OFF}"
  done

}

function start_iperf_server {
  for i in `seq 1 $1`;
  do
    echo -e "${COLOR_GREEN}Starting server${i} in ns${i}...${COLOR_OFF}"
    sudo ip netns exec ns${i} iperf3 --server --daemon --bind 10.0.${i}.1 -p 8000
    echo -e "${COLOR_GREEN}Server server${i} in ns${i} started.${COLOR_OFF}"
  done
}

function create_veth {
  sudo iptables -P FORWARD ACCEPT
  for i in `seq 1 $1`;
  do
  	sudo ip netns add ns${i}
  	sudo ip link add veth${i}_ type veth peer name veth${i}
  	sudo ip link set veth${i}_ netns ns${i}
  	sudo ip netns exec ns${i} ip link set dev veth${i}_ up
  	sudo ip link set dev veth${i} up
    sudo ip netns exec ns${i} ifconfig veth${i}_ 10.0.${i}.1/24 promisc
    sudo ip netns exec ns${i} route add default gw 10.0.${i}.254 veth${i}_
    sudo ifconfig veth${i} 10.0.${i}.254/24 up
    echo -e "${COLOR_GREEN}Namespace ns${i} created.${COLOR_OFF}"
  done
}

function delete_veth {
  for i in `seq 1 $1`;
  do
  	sudo ip link del veth${i} &> /dev/null
  	sudo ip netns del ns${i} &> /dev/null
  done
}

function ping_cycle {
  for i in `seq 1 $1`;
  do
    for j in `seq 1 $1`;
    do
      if [ "$i" -ne "$j" ]; then
        sudo ip netns exec ns$i ping 10.0.$j.1 -c 2 -i 0.5
      fi
    done
  done
}

function cleanup {
  set +e
  delete_veth 4
}
trap cleanup ERR

delete_veth 4

echo -e "${COLOR_YELLOW}Creating namespaces.${COLOR_OFF}"
create_veth 4
echo -e "${COLOR_GREEN}Namespaces created.\n${COLOR_OFF}"

echo -e "${COLOR_YELLOW}Let's check if everything is setup correctly.${COLOR_OFF}"
# All the namespaces try to ping each other
ping_cycle 4
echo -e "${COLOR_GREEN}Ping works, let's start the test.\n${COLOR_OFF}"
echo -e "${COLOR_GREEN}Type 'node index.js to start the proxy'.\n${COLOR_OFF}"

start_http_server 4

exit 0