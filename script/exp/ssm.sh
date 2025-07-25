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
        p ) POLICY=${OPTARG} ;;
        c ) COMPLEXITY=${OPTARG} ;;
        s ) SCRIPT=${OPTARG} ;;
        m ) MONITOR=true ;;
        r ) REPLICAS=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

### POLICY 0 ###

if [[ ${POLICY} == "0" ]]; then
    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "1" ]]; then
        echo Running policy 0 complexity 1

        PAYLOAD=$(printf 'a%.0s' {1..64})
        FRONTEND_ARGS=$(echo \'-H a:${PAYLOAD}\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p0-c1 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c1 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c1 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "2" ]]; then
        echo Running policy 0 complexity 2

        PAYLOAD=$(printf 'a%.0s' {1..1000})
        FRONTEND_ARGS=$(echo \'-H a:${PAYLOAD}\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p0-c2 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c2 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c2 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "3" ]]; then
        echo Running policy 0 complexity 3

        PAYLOAD=$(printf 'a%.0s' {1..1000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD}\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p0-c3 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c3 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c3 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "4" ]]; then
        echo Running policy 0 complexity 4

        PAYLOAD=$(printf 'a%.0s' {1..1000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD}\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p0-c4 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c4 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c4 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "5" ]]; then
        echo Running policy 0 complexity 5

        PAYLOAD=$(printf 'a%.0s' {1..1000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD},e:${PAYLOAD},f:${PAYLOAD},g:${PAYLOAD},h:${PAYLOAD}\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c5.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p0-c5 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c5.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c5 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p0-c5.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p0-c5 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
    fi
fi

### POLICY 1 ###

if [[ -z "${POLICY}" || ${POLICY} == "1" ]]; then
    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "1" ]]; then
        echo Running policy 1 complexity 1

        PAYLOAD=$(printf 'a%.0s' {1..1000})
        FRONTEND_ARGS=$(echo \'-H a:${PAYLOAD},b:${PAYLOAD}\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p1-c1 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p1-c1 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p1-c1 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p1-c1 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p1-c1 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "2" ]]; then
        echo Running policy 1 complexity 2

        PAYLOAD=$(printf 'a%.0s' {1..2000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD}\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p1-c2 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p1-c2 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p1-c2 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p1-c2 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p1-c2 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "3" ]]; then
        echo Running policy 1 complexity 3

        PAYLOAD=$(printf 'a%.0s' {1..2000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD},e:${PAYLOAD},f:${PAYLOAD},g:${PAYLOAD},h:${PAYLOAD}\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p1-c3 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p1-c3 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p1-c3 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p1-c3 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p1-c3 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "4" ]]; then
        echo Running policy 1 complexity 4

        PAYLOAD=$(printf 'a%.0s' {1..2000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD},e:${PAYLOAD},f:${PAYLOAD},g:${PAYLOAD},h:${PAYLOAD},i:${PAYLOAD},j:${PAYLOAD},k:${PAYLOAD},l:${PAYLOAD}\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p1-c4 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p1-c4 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p1-c4 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p1-c4 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p1-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p1-c4 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi
fi

### POLICY 2 ###

if [[ -z "${POLICY}" || ${POLICY} == "2" ]]; then
    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "1" ]]; then
        echo Running policy 2 complexity 1

        PAYLOAD=$(printf 'a%.0s' {1..1000})
        FRONTEND_ARGS=$(echo \'-H a:${PAYLOAD},b:${PAYLOAD}\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p2-c1 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p2-c1 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p2-c1 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p2-c1 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p2-c1 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "2" ]]; then
        echo Running policy 2 complexity 2

        PAYLOAD=$(printf 'a%.0s' {1..2000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD}\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p2-c2 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p2-c2 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p2-c2 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p2-c2 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p2-c2 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "3" ]]; then
        echo Running policy 2 complexity 3

        PAYLOAD=$(printf 'a%.0s' {1..2000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD},e:${PAYLOAD},f:${PAYLOAD},g:${PAYLOAD},h:${PAYLOAD}\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p2-c3 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p2-c3 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p2-c3 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p2-c3 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p2-c3 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "4" ]]; then
        echo Running policy 2 complexity 4

        PAYLOAD=$(printf 'a%.0s' {1..2000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD},e:${PAYLOAD},f:${PAYLOAD},g:${PAYLOAD},h:${PAYLOAD},i:${PAYLOAD},j:${PAYLOAD},k:${PAYLOAD},l:${PAYLOAD}\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p2-c4 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p2-c4 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p2-c4 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p2-c4 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p2-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p2-c4 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi

fi

### POLICY 3 ###

if [[ -z "${POLICY}" || ${POLICY} == "3" ]]; then
    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "1" ]]; then
        echo Running policy 3 complexity 1

        JWT=$(jwt encode --secret testtest12345678 '{"iss":"beeline", "aud": "echo"}')
        PAYLOAD=$(printf 'a%.0s' {1..1000})
        FRONTEND_ARGS=$(echo \'-H a:${PAYLOAD},b:${PAYLOAD},Authorization: Bearer $(echo ${JWT})\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p3-c1 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p3-c1 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p3-c1 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p3-c1 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c1.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p3-c1 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "2" ]]; then
        echo Running policy 3 complexity 2

        JWT=$(jwt encode --secret testtest12345678 '{"iss":"beeline", "aud": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')
        PAYLOAD=$(printf 'a%.0s' {1..2000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD},Authorization: Bearer $(echo ${JWT})\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p3-c2 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p3-c2 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p3-c2 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p3-c2 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c2.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p3-c2 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "3" ]]; then
        echo Running policy 3 complexity 3

        JWT=$(jwt encode --secret testtest12345678 '{"iss":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aud": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')
        PAYLOAD=$(printf 'a%.0s' {1..2000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD},e:${PAYLOAD},f:${PAYLOAD},g:${PAYLOAD},h:${PAYLOAD},Authorization: Bearer $(echo ${JWT})\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p3-c3 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p3-c3 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p3-c3 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p3-c3 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c3.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p3-c3 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "4" ]]; then
        echo Running policy 3 complexity 4

        JWT=$(jwt encode --secret testtest12345678 '{"iss":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aud": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')
        PAYLOAD=$(printf 'a%.0s' {1..2000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD},e:${PAYLOAD},f:${PAYLOAD},g:${PAYLOAD},h:${PAYLOAD},i:${PAYLOAD},j:${PAYLOAD},k:${PAYLOAD},l:${PAYLOAD},Authorization: Bearer $(echo ${JWT})\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p3-c4 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p3-c4 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p3-c4 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p3-c4 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p3-c4.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p3-c4 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi
fi

### POLICY 4 ###

if [[ -z "${POLICY}" || ${POLICY} == "4" ]]; then
    P4_SERVICES=${REPLICAS}
    P4_REPLICAS=$(echo "${REPLICAS} * 3" | bc)

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "1" ]]; then
        echo Running policy 4 complexity 1

        JWT=$(jwt encode --secret testtest12345678 '{"iss":"beeline", "aud": "echo"}')
        PAYLOAD=$(printf 'a%.0s' {1..1000})
        FRONTEND_ARGS=$(echo \'-H a:${PAYLOAD},b:${PAYLOAD},Authorization: Bearer $(echo ${JWT})\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c1.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p4-c1 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c1.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p4-c1 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c1.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p4-c1 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c1.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p4-c1 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c1.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p4-c1 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "2" ]]; then
        echo Running policy 4 complexity 2

        JWT=$(jwt encode --secret testtest12345678 '{"iss":"beeline", "aud": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')
        PAYLOAD=$(printf 'a%.0s' {1..2000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD},Authorization: Bearer $(echo ${JWT})\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c2.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p4-c2 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c2.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p4-c2 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c2.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p4-c2 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c2.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p4-c2 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c2.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p4-c2 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "3" ]]; then
        echo Running policy 4 complexity 3

        JWT=$(jwt encode --secret testtest12345678 '{"iss":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aud": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')
        PAYLOAD=$(printf 'a%.0s' {1..2000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD},e:${PAYLOAD},f:${PAYLOAD},g:${PAYLOAD},h:${PAYLOAD},Authorization: Bearer $(echo ${JWT})\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c3.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p4-c3 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c3.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p4-c3 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c3.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p4-c3 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c3.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p4-c3 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c3.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p4-c3 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi

    if [[ -z "${COMPLEXITY}" || ${COMPLEXITY} == "4" ]]; then
        echo Running policy 4 complexity 4

        JWT=$(jwt encode --secret testtest12345678 '{"iss":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aud": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')
        PAYLOAD=$(printf 'a%.0s' {1..2000})
        FRONTEND_ARGS=$(echo \'-Ha:${PAYLOAD},b:${PAYLOAD},c:${PAYLOAD},d:${PAYLOAD},e:${PAYLOAD},f:${PAYLOAD},g:${PAYLOAD},h:${PAYLOAD},i:${PAYLOAD},j:${PAYLOAD},k:${PAYLOAD},l:${PAYLOAD},Authorization: Bearer $(echo ${JWT})\')
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c4.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}-p4-c4 -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c4.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p4-c4 -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c4.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}-p4-c4 -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}

        if [[ ${MONITOR} == true ]]; then
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c4.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p4-c4 -p none -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
            script/bench.sh sm -e "PROXY_CONFIG=ssm-p4-c4.yaml l REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-vanilla.yaml -n ${NAME}-p4-c4 -p none_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO} -m ${MONITOR}
        fi
    fi
fi
