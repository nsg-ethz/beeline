#!/bin/bash

SCRIPT=k6/tput.js

# Parse arguments
while getopts "f:t:n:p:c:s:" opt; do
    case $opt in
        f ) FROM=${OPTARG} ;;
        t ) TO=${OPTARG} ;;
        n ) NAME=${OPTARG} ;;
        p ) POLICY=${OPTARG} ;;
        c ) COMPLEXITY=${OPTARG} ;;
        s ) SCRIPT=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

### POLICY 1 ###

if [[ -z "${POLICY}" || ${POLICY} == "1" ]]; then
    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "1" ]]; then
        echo Running policy 1 complexity 1

        PAYLOAD=$(printf 'a%.0s' {1..64})
        FRONTEND_ARGS=$(echo \'-H asdf:${PAYLOAD}\')
        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p1-c1.yaml REPLICAS=3 FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p1-c1 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p1-c1.yaml REPLICAS=3 FRONTEND_ARGS='-H asdf:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'" -c docker/ssm-envoy.yaml -n ${NAME}-p1-c1 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "2" ]]; then
        echo Running policy 1 complexity 2

        PAYLOAD=$(printf 'a%.0s' {1..1000})
        FRONTEND_ARGS=$(echo \'-H asdf:${PAYLOAD}\')
        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p1-c2.yaml REPLICAS=3 FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p1-c2 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p1-c2.yaml REPLICAS=3 FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p1-c2 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "3" ]]; then
        echo Running policy 1 complexity 3

        PAYLOAD=$(printf 'a%.0s' {1..1000})
        FRONTEND_ARGS=$(echo \'-Hasdf:${PAYLOAD},qwer:${PAYLOAD},zxcv:${PAYLOAD}\')
        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p1-c3.yaml REPLICAS=3 FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p1-c3 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p1-c3.yaml REPLICAS=3 FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p1-c3 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "4" ]]; then
        echo Running policy 1 complexity 4

        PAYLOAD=$(printf 'a%.0s' {1..2000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD},e:${PAYLOAD},f:${PAYLOAD}\')
        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p1-c4.yaml REPLICAS=3 FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p1-c4 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p1-c4.yaml REPLICAS=3 FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p1-c4 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi
fi

### POLICY 2 ###

if [[ -z "${POLICY}" || ${POLICY} == "2" ]]; then
    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "1" ]]; then
        echo Running policy 2 complexity 1

        JWT=$(jwt encode --secret testtest12345678 '{"iss":"beeline", "aud": "echo"}')
        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p2-c1.yaml REPLICAS=3 FRONTEND_ARGS=\"-H Authorization: Bearer $(echo ${JWT})\"" -c docker/ssm-beeline.yaml -n ${NAME}-p2-c1 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p2-c1.yaml REPLICAS=3 FRONTEND_ARGS=\"-H Authorization: Bearer $(echo ${JWT})\"" -c docker/ssm-envoy.yaml -n ${NAME}-p2-c1 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "2" ]]; then
        echo Running policy 2 complexity 2

        JWT=$(jwt encode --secret testtest12345678 '{"iss":"beeline", "aud": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')
        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p2-c2.yaml REPLICAS=3 FRONTEND_ARGS=\"-H Authorization: Bearer $(echo ${JWT})\"" -c docker/ssm-beeline.yaml -n ${NAME}-p2-c2 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p2-c2.yaml REPLICAS=3 FRONTEND_ARGS=\"-H Authorization: Bearer $(echo ${JWT})\"" -c docker/ssm-envoy.yaml -n ${NAME}-p2-c2 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "3" ]]; then
        echo Running policy 2 complexity 3

        JWT=$(jwt encode --secret testtest12345678 '{"iss":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aud": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')
        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p2-c3.yaml REPLICAS=3 FRONTEND_ARGS=\"-H Authorization: Bearer $(echo ${JWT})\"" -c docker/ssm-beeline.yaml -n ${NAME}-p2-c3 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p2-c3.yaml REPLICAS=3 FRONTEND_ARGS=\"-H Authorization: Bearer $(echo ${JWT})\"" -c docker/ssm-envoy.yaml -n ${NAME}-p2-c3 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi
fi

### POLICY 3 ###

if [[ -z "${POLICY}" || ${POLICY} == "3" ]]; then
    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "1" ]]; then
        echo Running policy 3 complexity 1

        PAYLOAD=$(printf 'a%.0s' {1..64})
        FRONTEND_ARGS=$(echo \'-H asdf:${PAYLOAD}\')
        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p3-c1.yaml REPLICAS=9 SERVICES=3 FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p3-c1 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p3-c1.yaml REPLICAS=9 SERVICES=3 FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p3-c1 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "2" ]]; then
        echo Running policy 3 complexity 2

        PAYLOAD=$(printf 'a%.0s' {1..1000})
        FRONTEND_ARGS=$(echo \'-H asdf:${PAYLOAD}\')
        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p3-c2.yaml REPLICAS=9 SERVICES=3 FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p3-c2 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p3-c2.yaml REPLICAS=9 SERVICES=3 FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p3-c2 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "3" ]]; then
        echo Running policy 3 complexity 3

        PAYLOAD=$(printf 'a%.0s' {1..1000})
        FRONTEND_ARGS=$(echo \'-Hasdf:${PAYLOAD},qwer:${PAYLOAD},zxcv:${PAYLOAD}\')
        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p3-c3.yaml REPLICAS=9 SERVICES=3 FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p3-c3 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p3-c3.yaml REPLICAS=9 SERVICES=3 FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p3-c3 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi
fi

### POLICY 4 ###

if [[ -z "${POLICY}" || ${POLICY} == "4" ]]; then
    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "1" ]]; then
        echo Running policy 4 complexity 1

        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p4-c1.yaml REPLICAS=3" -c docker/ssm-beeline.yaml -n ${NAME}-p4-c1 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p4-c1.yaml REPLICAS=3" -c docker/ssm-envoy.yaml -n ${NAME}-p4-c1 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "2" ]]; then
        echo Running policy 4 complexity 2

        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p4-c2.yaml REPLICAS=3" -c docker/ssm-beeline.yaml -n ${NAME}-p4-c2 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p4-c2.yaml REPLICAS=3" -c docker/ssm-envoy.yaml -n ${NAME}-p4-c2 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "3" ]]; then
        echo Running policy 4 complexity 3

        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p4-c3.yaml REPLICAS=3" -c docker/ssm-beeline.yaml -n ${NAME}-p4-c3 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p4-c3.yaml REPLICAS=3" -c docker/ssm-envoy.yaml -n ${NAME}-p4-c3 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi
fi

### POLICY 5 ###

if [[ -z "${POLICY}" || ${POLICY} == "5" ]]; then
    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "1" ]]; then
        echo Running policy 5 complexity 1

        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p5-c1.yaml REPLICAS=3" -c docker/ssm-beeline.yaml -n ${NAME}-p5-c1 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p5-c1.yaml REPLICAS=3" -c docker/ssm-envoy.yaml -n ${NAME}-p5-c1 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "2" ]]; then
        echo Running policy 5 complexity 2

        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p5-c2.yaml REPLICAS=3" -c docker/ssm-beeline.yaml -n ${NAME}-p5-c2 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p5-c2.yaml REPLICAS=3" -c docker/ssm-envoy.yaml -n ${NAME}-p5-c2 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "3" ]]; then
        echo Running policy 5 complexity 3

        script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ssm-p5-c3.yaml REPLICAS=3" -c docker/ssm-beeline.yaml -n ${NAME}-p5-c3 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
        script/bench.sh sm -e "ENVOY_CONFIG=config/envoy/ssm-p5-c3.yaml REPLICAS=3" -c docker/ssm-envoy.yaml -n ${NAME}-p5-c3 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
    fi
fi
