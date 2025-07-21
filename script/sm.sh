#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

MONITOR=0
ACTION=$1
shift 1

function stop_probes {
    sudo killall -SIGINT funclatency-bpfcc >/dev/null 2>&1
}

# Parse arguments
while getopts "c:n:p:e:m" opt; do
    case $opt in
        c ) DOCKER_CONFIG=${OPTARG} ;;
        n ) NAME=${OPTARG} ;;
        p ) PROXY=${OPTARG} ;;
        e ) EPOCH=${OPTARG} ;;
        m ) MONITOR=1 ;;
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
SUMMARY_DIR=${ROOT}/../res/runs/${NAME}
ENVOY_BIN="${HOME}/envoy/bazel-out/k8-opt/bin/source/exe/envoy-static"
mkdir -p ${SUMMARY_DIR}

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

        stop_probes
        sudo systemctl stop sm-proxy.scope > /dev/null 2>&1
        sudo systemctl stop sm-proxy-opt.scope > /dev/null 2>&1
        sudo systemctl stop sm-bpf-monitor.scope > /dev/null 2>&1
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

        if [[ "${DOCKER_CONFIG}" == *ssm* ]]; then
            SIDECAR_CONFIG=${ROOT}/../config/envoy/${PROXY_CONFIG}

            # envoy is not loaded by docker
            # this is because uprobes do not work well in docker
            SIDECAR_NAME=$(docker ps | grep sidecar | awk '{ print $NF }')
            SIDECAR_NS=$(docker inspect ${SIDECAR_NAME} -f '{{.NetworkSettings.SandboxKey}}')
            sudo -b systemd-run -q --scope -u sm-proxy --slice beeline.slice nsenter --net=${SIDECAR_NS} ${ENVOY_BIN} -c ${SIDECAR_CONFIG} > /dev/null 2>&1
            echo -e "${COLOR_GREEN}Launched envoy${COLOR_OFF}"
        fi

        CWD=${PWD}
        if [ "${PROXY}" = "beeline" ]; then
            BEELINE_BIN=${ROOT}/../target/release/${PROXY}
            BEELINE_CONFIG=${ROOT}/../config/beeline/${PROXY_CONFIG}
            cd ${ROOT}/..
            CONFIG=${BEELINE_CONFIG} BPF_PROFILE=${MONITOR} cargo b -r -p beeline
            BPF_PROFILE=${MONITOR} sudo -b -E systemd-run -q --scope -u sm-proxy-opt --slice beeline.slice ${BEELINE_BIN} -c ${BEELINE_CONFIG}
            echo -e "${COLOR_GREEN}Launched beeline${COLOR_OFF}"
        elif [ "${PROXY}" = "baseline" ]; then
            PROXY_BIN=${ROOT}/../target/release/${PROXY}
            sudo -b systemd-run -q --scope -u sm-proxy-opt --slice beeline.slice ${PROXY_BIN} -a 172.17.0.1
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

        if [[ "${MONITOR}" = 1 ]]; then
            if [[ "${PROXY}" = "beeline" ]]; then
                sudo -b -E systemd-run -q --scope -u sm-bpf-monitor bpftool prog tracelog > ${SUMMARY_DIR}/${PROXY}-bpf-e${EPOCH}.log
            elif [[ "${PROXY}" = "baseline" || "${PROXY}" = "envoy" ]]; then
                ENVOY_PID=$(pidof envoy-static)

                echo -e "${COLOR_YELLOW}Attaching probes...${COLOR_OFF}"
                sudo -b funclatency-bpfcc -p ${ENVOY_PID} ${ENVOY_BIN}:"*BalsaParser*execute*" > ${SUMMARY_DIR}/${PROXY}-bpf-${PROXY}.parse-e${EPOCH}.log 2>/dev/null
                sudo -b funclatency-bpfcc -p ${ENVOY_PID} -r ${ENVOY_BIN}:"^.*on(Read|Write)Ready.*$" > ${SUMMARY_DIR}/${PROXY}-bpf-${PROXY}.user-e${EPOCH}.log 2>/dev/null
                sudo -b funclatency-bpfcc -p ${ENVOY_PID} "process_backlog" > ${SUMMARY_DIR}/${PROXY}-bpf-${PROXY}.ipc-e${EPOCH}.log 2>/dev/null
                sudo -b funclatency-bpfcc -p ${ENVOY_PID} "ep_send_events" > ${SUMMARY_DIR}/${PROXY}-bpf-${PROXY}.epoll-e${EPOCH}.log 2>/dev/null
                sudo -b funclatency-bpfcc -p ${ENVOY_PID} "__sys_sendto" > ${SUMMARY_DIR}/${PROXY}-bpf-${PROXY}.write-e${EPOCH}.log 2>/dev/null
                sudo -b funclatency-bpfcc -p ${ENVOY_PID} "vfs_readv" > ${SUMMARY_DIR}/${PROXY}-bpf-${PROXY}.read-e${EPOCH}.log 2>/dev/null

                sleep 5
            fi
        fi

        sudo -b systemd-run -q --scope -u sm-cpu ${ROOT}/capture-cpu.sh -n ${NAME} -p ${PROXY} -e ${EPOCH}
        ;;

    down)
        CPU_SYSTEM=0-39

        stop_probes
        sudo systemctl stop sm-proxy.scope > /dev/null 2>&1
        sudo systemctl stop sm-proxy-opt.scope > /dev/null 2>&1
        sudo systemctl stop sm-bpf-monitor.scope > /dev/null 2>&1
        sudo systemctl stop sm-cpu.scope > /dev/null 2>&1

        if [[ "${MONITOR}" = 1 ]]; then
            if [[ "${PROXY}" = "beeline" ]]; then
                grep "sk_msg total" ${SUMMARY_DIR}/${PROXY}-bpf-e${EPOCH}.log > ${SUMMARY_DIR}/${PROXY}-bpf-beeline.user-e${EPOCH}.log
                grep "parse total" ${SUMMARY_DIR}/${PROXY}-bpf-e${EPOCH}.log > ${SUMMARY_DIR}/${PROXY}-bpf-beeline.parse-e${EPOCH}.log
                rm ${SUMMARY_DIR}/${PROXY}-bpf-e${EPOCH}.log
            elif [ "${PROXY}" = "naive" ] || [ "${PROXY}" = "naive_fp" ]; then
                grep "other total" ${SUMMARY_DIR}/${PROXY}-bpf-e${EPOCH}.log > ${SUMMARY_DIR}/${PROXY}-bpf-naive.user-e${EPOCH}.log
                grep "parse total" ${SUMMARY_DIR}/${PROXY}-bpf-e${EPOCH}.log > ${SUMMARY_DIR}/${PROXY}-bpf-naive.parse-e${EPOCH}.log
                rm ${SUMMARY_DIR}/${PROXY}-bpf-e${EPOCH}.log
            fi
        fi

        docker compose -f ${DOCKER_CONFIG} down

        echo -e "${COLOR_YELLOW}Setting CPU governor${COLOR_OFF}"
        echo schedutil | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

        echo -e "${COLOR_YELLOW}Resetting CPUs${COLOR_OFF}"
        sudo systemctl set-property --runtime user.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime system.slice AllowedCPUs=${CPU_SYSTEM}
        sudo systemctl set-property --runtime init.scope AllowedCPUs=${CPU_SYSTEM}
        ;;

esac
