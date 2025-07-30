#!/bin/bash

SCRIPT=k6/tput.js
MONITOR=false
REPLICAS=1

# Parse arguments
while getopts "f:t:n:p:c:s:mr:" opt; do
    case $opt in
        f ) FROM=${OPTARG} ;;
        t ) TO=${OPTARG} ;;
        n ) NAME=${OPTARG} ;;
        c ) COMPLEXITY=${OPTARG} ;;
        s ) SCRIPT=${OPTARG} ;;
        r ) REPLICAS=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

### POLICY 0 ###

if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "1" ]]; then
    echo Running policy 0 complexity 1

    PAYLOAD=$(printf 'a%.0s' {1..64})
    FRONTEND_ARGS=$(echo \'-H a:${PAYLOAD}\')
    script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p0-c1 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
    script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c1 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c1 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO}
fi

if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "2" ]]; then
    echo Running policy 0 complexity 2

    PAYLOAD=$(printf 'a%.0s' {1..1000})
    FRONTEND_ARGS=$(echo \'-H a:${PAYLOAD}\')
    script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p0-c2 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
    script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c2 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c2 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO}
fi

if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "3" ]]; then
    echo Running policy 0 complexity 3

    PAYLOAD=$(printf 'a%.0s' {1..1000})
    FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD}\')
    script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p0-c3 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
    script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c3 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c3 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO}
fi

if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "4" ]]; then
    echo Running policy 0 complexity 4

    PAYLOAD=$(printf 'a%.0s' {1..1000})
    FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD}\')
    script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p0-c4 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
    script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c4 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c4 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO}
fi

if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "5" ]]; then
    echo Running policy 0 complexity 5

    PAYLOAD=$(printf 'a%.0s' {1..1000})
    FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD},e:${PAYLOAD},f:${PAYLOAD},g:${PAYLOAD},h:${PAYLOAD}\')
    script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c5.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p0-c5 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
    script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c5.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c5 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c5.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c5 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO}
fi
