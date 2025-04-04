#!/bin/bash

ROOT=$(dirname "$(readlink -f "$0")")
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

DIRECTION=$1
EXPERIMENT=$2
shift 2

if [ $# -ne 2 ]; then
    echo "Usage: $0 [up|down] experiment"
    exit 1
fi

# Check if DIRECTION is valid
if [ ${DIRECTION} != "up" ] && [ ${DIRECTION} != "down" ]; then
    echo "Unknown Command"
    exit 1
fi

# Parse arguments
while getopts "n:p:" opt; do
    case $opt in
        n ) NAME=${OPTARG} ;;
        p ) PROXY=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

if [ -z "${NAME}" ]; then
    echo "Need to supply experiment name"
    exit 1
fi

if [ -z "${PROXY}" ]; then
    echo "Need to supply proxy name"
    exit 1
fi

case ${DIRECTION} in
    "up")

        CPU_SYSTEM=0,1,20,21
        CPU_BEELINE=2-19,22-39

        echo -e "${COLOR_YELLOW}Assigning CPUs ${CPU_BEELINE} to experiment${COLOR_OFF}"
        sudo systemctl set-property --runtime user.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime system.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime init.scope AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime beeline.slice AllowedCPUs=${CPU_BEELINE}


        docker compose -f ${EXPERIMENT} up -d --force-recreate

        ${ROOT}/capture-cpu.sh -n ${NAME} -p ${PROXY} &
        ;;
    "down")
        pkill capture-cpu.sh 2>&1 >/dev/null

        CPU_SYSTEM=0-39
        echo -e "${COLOR_YELLOW}${COLOR_OFF}"
        sudo systemctl set-property --runtime user.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime system.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime init.scope AllowedCPUs=${CPU_SYSTEM}

        docker compose -f ${EXPERIMENT} down
        ;;
esac
