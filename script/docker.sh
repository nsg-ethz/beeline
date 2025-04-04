#!/bin/bash

ROOT=$(dirname "$(readlink -f "$0")")
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

# Parse arguments
while getopts "f:n:p:" opt; do
    case $opt in
        f ) FILE=${OPTARG} ;;
        n ) NAME=${OPTARG} ;;
        p ) PROXY=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

if [ -z "${FILE}" ]; then
    echo "Need to supply docker compose file"
    exit 1
fi

if [ -z "${NAME}" ]; then
    echo "Need to supply experiment name"
    exit 1
fi

if [ -z "${PROXY}" ]; then
    echo "Need to supply proxy name"
    exit 1
fi

function stop_experiment {
    pkill capture-cpu.sh 2>&1 >/dev/null

    CPU_SYSTEM=0-39
    echo -e "${COLOR_YELLOW}Resetting CPUs${COLOR_OFF}"
    sudo systemctl set-property --runtime user.slice AllowedCPUs=${CPU_SYSTEM}
    sudo systemctl set-property --runtime system.slice AllowedCPUs=${CPU_SYSTEM}
    sudo systemctl set-property --runtime init.scope AllowedCPUs=${CPU_SYSTEM}
}

trap stop_experiment INT

CPU_SYSTEM=0,1,20,21
CPU_BEELINE=2-19,22-39

echo -e "${COLOR_YELLOW}Assigning CPUs ${CPU_BEELINE} to experiment${COLOR_OFF}"
sudo systemctl set-property --runtime user.slice AllowedCPUs=${CPU_SYSTEM}
sudo systemctl set-property --runtime system.slice AllowedCPUs=${CPU_SYSTEM}
sudo systemctl set-property --runtime init.scope AllowedCPUs=${CPU_SYSTEM}
sudo systemctl set-property --runtime beeline.slice AllowedCPUs=${CPU_BEELINE}

${ROOT}/capture-cpu.sh -n ${NAME} -p ${PROXY} &

docker compose -f ${FILE} up --force-recreate

stop_experiment
