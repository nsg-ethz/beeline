#!/bin/bash

ROOT=$(dirname "$(readlink -f "$0")")
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

DIRECTION=$1
EXPERIMENT=$2

if [ $# -ne 2 ]; then
    echo "Usage: $0 [up|down] experiment"
    exit 1
fi

# Check if DIRECTION is valid
if [ ${DIRECTION} != "up" ] && [ ${DIRECTION} != "down" ]; then
    echo "Unknown Command"
    exit 1
fi

# Now you can use the arguments
case ${DIRECTION} in
    "up")

        CPU_SYSTEM=0,20
        CPU_BEELINE=1-19,21-39

        echo -e "${COLOR_YELLOW}Assigning CPUs ${CPU_BEELINE} to experiment${COLOR_OFF}"
        sudo systemctl set-property --runtime user.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime system.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime init.scope AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime beeline.slice AllowedCPUs=${CPU_BEELINE}


        docker compose -f ${EXPERIMENT} up -d --force-recreate
        ;;
    "down")
        CPU_SYSTEM=0-39
        echo -e "${COLOR_YELLOW}${COLOR_OFF}"
        sudo systemctl set-property --runtime user.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime system.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime init.scope AllowedCPUs=${CPU_SYSTEM}

        docker compose -f ${EXPERIMENT} down
        ;;
esac
