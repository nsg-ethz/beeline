#!/bin/bash

ROOT=$(dirname "$(readlink -f "$0")")
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

ACTION=$1
shift 1

# Parse arguments
while getopts "c:n:p:e:" opt; do
    case $opt in
        c ) DOCKER_CONFIG=${OPTARG} ;;
        n ) NAME=${OPTARG} ;;
        p ) PROXY=${OPTARG} ;;
        e ) EPOCH=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

if [ -z "${DOCKER_CONFIG}" ]; then
    echo "Need to supply docker compose file"
    exit 1
fi

source ${ROOT}/../venv/bin/activate

case ${ACTION} in
    up)
        if [ -z "${NAME}" ]; then
            echo "Need to supply experiment name"
            exit 1
        fi

        if [ -z "${PROXY}" ]; then
            echo "Need to supply proxy name"
            exit 1
        fi

        CPU_SYSTEM=0,1,20,21
        CPU_BEELINE=2-19,22-39

        # clean up just to be safe
        CONTAINERS=$(docker ps -a -q)
        if [ ! -z "$CONTAINERS" ]; then
            docker stop $CONTAINERS
        fi
        docker container prune -f
        docker volume prune -f
        docker network prune -f

        sudo systemctl stop sm-proxy.scope > /dev/null 2>&1
        sudo systemctl stop sm-cpu.scope > /dev/null 2>&1

        echo -e "${COLOR_YELLOW}Setting CPU governor${COLOR_OFF}"
        echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

        echo -e "${COLOR_YELLOW}Assigning CPUs ${CPU_BEELINE} to experiment${COLOR_OFF}"
        sudo systemctl set-property --runtime user.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime system.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime init.scope AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime beeline.slice AllowedCPUs=${CPU_BEELINE}

        # this doesn't seem like a good idea but it works
        sudo chmod -R o+r ${ROOT}/../test/social_network/config-*
        sudo chmod -R o+r ${ROOT}/../test/media_service/config-*
        sudo chmod -R o+r ${ROOT}/../config/envoy/*.yaml

        docker compose -f ${DOCKER_CONFIG} up --wait -d --force-recreate

        CWD=${PWD}
        if [ "${PROXY}" = "beeline" ]; then
            PROXY_BIN=${ROOT}/../target/release/${PROXY}
            cd ${ROOT}/..
            CONFIG=${ROOT}/../${BEELINE_CONFIG} cargo b -r -p beeline
            sudo -b systemd-run -q --scope -u sm-proxy --slice beeline.slice ${PROXY_BIN} -c ${ROOT}/../${BEELINE_CONFIG}
            echo -e "${COLOR_GREEN}Launched beeline${COLOR_OFF}"
        elif [ "${PROXY}" = "baseline" ]; then
            PROXY_BIN=${ROOT}/../target/release/${PROXY}
            sudo -b systemd-run -q --scope -u sm-proxy --slice beeline.slice ${PROXY_BIN} -a 172.17.0.1
            echo -e "${COLOR_GREEN}Launched baseline${COLOR_OFF}"
        fi

        sleep 5

        # populate dbs with data
        if [[ "${DOCKER_CONFIG}" == *sn* ]]; then
            cd ${ROOT}/../test/social_network
            python3 scripts/init_social_graph.py
        elif [[ "${DOCKER_CONFIG}" == *ms* ]]; then
            cd ${ROOT}/../test/media_service/scripts
            ./register_users.sh
            ./register_movies.sh
        fi
        cd ${CWD}

        sudo -b systemd-run -q --scope -u sm-cpu ${ROOT}/capture-cpu.sh -n ${NAME} -p ${PROXY} -e ${EPOCH}
        ;;

    down)
        CPU_SYSTEM=0-39

        sudo systemctl stop sm-proxy.scope > /dev/null 2>&1
        sudo systemctl stop sm-cpu.scope > /dev/null 2>&1

        docker compose -f ${DOCKER_CONFIG} down

        echo -e "${COLOR_YELLOW}Setting CPU governor${COLOR_OFF}"
        echo schedutil | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

        echo -e "${COLOR_YELLOW}Resetting CPUs${COLOR_OFF}"
        sudo systemctl set-property --runtime user.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime system.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime init.scope AllowedCPUs=${CPU_SYSTEM}
        ;;

esac
