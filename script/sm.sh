#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

ACTION=$1
shift 1

# Parse arguments
while getopts "c:n:p:e:m" opt; do
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

ROOT=$(dirname "$(readlink -f "$0")")
DOCKER_CONFIG=${ROOT}/../${DOCKER_CONFIG}
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}
mkdir -p ${SUMMARY_DIR}

cd ${ROOT}
source ${ROOT}/../venv/bin/activate

function health_check {
    for i in $(seq 1 20); do
        curl --connect-timeout 0.5 -s $1
        if [[ $? == 0 ]]; then
            break
        fi
        sleep 1
    done
}

function launch_proxy {
    PWD=$(pwd)
    cd ${ROOT}/..

    if [[ "${PROXY}" == "beeline" ]]; then
        BEELINE_BIN=${ROOT}/../target/release/beeline
        BEELINE_CONFIG=${ROOT}/../config/beeline/${PROXY_CONFIG}
        CONFIG=${BEELINE_CONFIG} BPF_PROFILE=1 cargo b -r -p beeline

        BPF_PROFILE=1 sudo -b ${BEELINE_BIN} -c ${BEELINE_CONFIG} > ${SUMMARY_DIR}/${PROXY}-e${EPOCH}.log
        health_check 172.17.0.1:9999

        if [[ -z $(pidof beeline) ]]; then
            echo -e "${COLOR_RED}Beeline crashed${COLOR_OFF}"
            exit 1
        else
            echo -e "${COLOR_GREEN}Launched beeline${COLOR_OFF}"
        fi
        sudo -b bpftool prog tracelog > ${SUMMARY_DIR}/${PROXY}-rt-e${EPOCH}.log
    else
        if [[ "${PROXY}" == *l4fp ]]; then
            PROXY_BIN=${ROOT}/../target/release/l4fp
            cargo b -r -p l4fp

            sudo -b ${PROXY_BIN} -c 172.18.0.0/24
            echo -e "${COLOR_GREEN}Launched L4 fast path${COLOR_OFF}"

            sleep 3
        fi
        if [[ "${PROXY}" == envoy* ]]; then
            docker compose -f ${DOCKER_CONFIG} --progress plain up sidecar --wait -d
            SIDECAR_CONFIG=${ROOT}/../config/envoy/${PROXY_CONFIG}

            # envoy is not loaded by docker
            # this is because uprobes do not work well in docker
            SIDECAR_NAME=$(docker ps | grep sidecar | awk '{ print $NF }')
            SIDECAR_NS=$(docker inspect ${SIDECAR_NAME} -f '{{.NetworkSettings.SandboxKey}}')

            ENVOY_OUT=${SUMMARY_DIR}/${PROXY}-rt-e${EPOCH}.log
            sudo -b nsenter --net=${SIDECAR_NS} envoy -c ${SIDECAR_CONFIG} > ${ENVOY_OUT} 2>&1
            echo -e "${COLOR_GREEN}Launched envoy${COLOR_OFF}"

            sleep 5
            if [[ -z $(pidof envoy) ]]; then
                echo -e "${COLOR_RED}Envoy crashed${COLOR_OFF}"
                exit 1
            fi
        else
            sleep 3
        fi
    fi

    cd ${PWD}
}

function stop_services {
    sudo killall envoy > /dev/null 2>&1
    sudo killall beeline > /dev/null 2>&1
    sudo killall l4fp > /dev/null 2>&1
    sudo killall bpftool > /dev/null 2>&1
}

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

        # clean up just to be safe
        CONTAINERS=$(docker ps -a -q)
        if [ ! -z "$CONTAINERS" ]; then
            docker stop $CONTAINERS
        fi
        docker container prune -f
        docker volume prune -f
        docker network prune -f

        stop_services

        echo -e "${COLOR_YELLOW}Setting CPU governor${COLOR_OFF}"
        echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

        # this doesn't seem like a good idea but it works
        sudo chmod -R o+r ${ROOT}/../test/social_network/config-*
        sudo chmod -R o+r ${ROOT}/../test/media_service/config-*
        sudo chmod -R o+r ${ROOT}/../test/hotel_reservation/config-*
        sudo chmod -R o+r ${ROOT}/../config/envoy/*.yaml
        sudo chmod -R o+r ${ROOT}/../res/pem/*.pem

        launch_proxy
        docker compose -f ${DOCKER_CONFIG} --progress plain up --wait -d

        # populate dbs with data
        if [[ "${DOCKER_CONFIG}" == *sn* ]]; then
            echo -e "${COLOR_YELLOW}Preparing social network...${COLOR_OFF}"
            cd ${ROOT}/../test/social_network
            python3 scripts/init_social_graph.py
        elif [[ "${DOCKER_CONFIG}" == *ms* ]]; then
            echo -e "${COLOR_YELLOW}Preparing media service...${COLOR_OFF}"
            cd ${ROOT}/../test/media_service/scripts
            ./register_users.sh
            ./register_movies.sh
        elif [[ "${DOCKER_CONFIG}" == *hr* ]]; then
            echo "Waiting until everything is ready..."
            sleep 5
        fi

        # restart services to reset statistics
        if [[ "${DOCKER_CONFIG}" == *sn* || "${DOCKER_CONFIG}" == *ms* ]]; then
            stop_services
            launch_proxy
        fi
        ;;

    down)
        echo -e "${COLOR_YELLOW}Setting CPU governor${COLOR_OFF}"
        echo schedutil | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

        stop_services

        if [[ "${PROXY}" == "beeline" ]]; then
            grep "sk_msg total" ${SUMMARY_DIR}/${PROXY}-rt-e${EPOCH}.log > ${SUMMARY_DIR}/${PROXY}-rt-user-e${EPOCH}.log
            grep "parse total" ${SUMMARY_DIR}/${PROXY}-rt-e${EPOCH}.log > ${SUMMARY_DIR}/${PROXY}-rt-parse-e${EPOCH}.log
            grep "ctx total" ${SUMMARY_DIR}/${PROXY}-rt-e${EPOCH}.log > ${SUMMARY_DIR}/${PROXY}-rt-ctx-e${EPOCH}.log
            rm ${SUMMARY_DIR}/${PROXY}-rt-e${EPOCH}.log
        elif [[ "${PROXY}" == envoy* ]]; then
            grep "ipc total" ${SUMMARY_DIR}/${PROXY}-rt-e${EPOCH}.log > ${SUMMARY_DIR}/${PROXY}-rt-ipc-e${EPOCH}.log
            grep "parse total" ${SUMMARY_DIR}/${PROXY}-rt-e${EPOCH}.log > ${SUMMARY_DIR}/${PROXY}-rt-parse-e${EPOCH}.log
            grep "user total" ${SUMMARY_DIR}/${PROXY}-rt-e${EPOCH}.log > ${SUMMARY_DIR}/${PROXY}-rt-user-e${EPOCH}.log
            rm ${SUMMARY_DIR}/${PROXY}-rt-e${EPOCH}.log
        fi

        docker compose -f ${DOCKER_CONFIG} --progress plain down
        ;;

esac
