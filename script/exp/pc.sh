#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

REPLICAS=1

# Parse arguments
while getopts "f:t:n:p:s:r:" opt; do
    case $opt in
        f ) FROM=${OPTARG} ;;
        t ) TO=${OPTARG} ;;
        n ) NAME=${OPTARG} ;;
        p ) POLICY=${OPTARG} ;;
        r ) REPLICAS=${OPTARG} ;;
        s ) SCRIPT=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

DEST_HOST="moonshine"
ROOT=$(dirname "$(readlink -f "$0")")
SCRIPT=${ROOT}/../../${SCRIPT:-/k6/pc.js}
CONFIG=${ROOT}/../../res/pol/pc.yaml
BEELINE_BIN=${ROOT}/../../target/release/beeline
POLGEN_BIN=${ROOT}/../../target/release/polgen
cargo b -r --bin polgen

function validate_policy {
    ssh -t ${DEST_HOST} "source ~/.profile && cd ${PWD} && CONFIG=${ROOT}/../../config/beeline/pc.yaml cargo r -r -p beeline -- --validate"
}

function frontend_args {
    alphabet=({a..z})
    args="-H"

    for i in "${!alphabet[@]}"; do
        index=$((i + 1))
        letter="${alphabet[$i]}"
        args+="${letter}:${PAYLOAD},"

        if [[ $index -eq $1 ]]; then
            break
        fi
    done

    echo "${args::-1}"
}

function compute_complexity {
    PROG=$(echo "scale=5; $1 / 24000" | bc)
    cmp=$(echo "$PROG > 1" | bc)
    if [[ $cmp -eq 1 ]]; then
        PROG=1
    fi

    n2=$(echo "$PROG * 100" | bc)
    n2=$(printf "%.0f" $n2)
    n3=$(echo "$PROG * 1500" | bc)
    n3=$(printf "%.0f" $n3)
    m3=$n3
    n4=$n1
}

if [[ ${POLICY} == "0" ]]; then
    echo Running policy 0

    for n1 in $(seq 1 10); do
        for m1 in $(seq 1000 1000 16000); do
            LEN=$(echo "${n1} * ${m1}" | bc)
            if [[ ${LEN} -gt 24000 ]]; then
                continue
            fi
            compute_complexity ${LEN}

            ${POLGEN_BIN} -t beeline --template ${ROOT}/../../config/beeline/ssm-p0.yaml --n1 ${n1} --m1 ${m1} -o ${CONFIG}
            scp -q ${CONFIG} ${DEST_HOST}:${ROOT}/../../config/beeline/pc.yaml

            # check if beeline can compile this policy
            validate_policy
            if [[ $? -ne 0 ]]; then
                echo -e "${COLOR_YELLOW}Beeline failed to compile policy. Skipping${COLOR_OFF}"
                continue
            fi

            ${POLGEN_BIN} -t envoy --n1 ${n1} --m1 ${m1} -o ${CONFIG}
            scp -q ${CONFIG} ${DEST_HOST}:${ROOT}/../../config/envoy/pc.yaml

            PAYLOAD=$(eval "printf 'a%.0s' {1..$m1}")
            FRONTEND_ARGS=$(frontend_args $n1)

            script/bench.sh sm -e "PROXY_CONFIG=pc.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}/p0-n1-${n1}-m1-${m1} -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
            script/bench.sh sm -e "PROXY_CONFIG=pc.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}/p0-n1-${n1}-m1-${m1} -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
            script/bench.sh sm -e "PROXY_CONFIG=pc.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}/p0-n1-${n1}-m1-${m1} -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO}
        done
    done
fi

if [[ -z "${POLICY}" || ${POLICY} == "1" ]]; then
    echo Running policy 1

    for n1 in $(seq 1 10); do
        for m1 in $(seq 1000 1000 16000); do
            LEN=$(echo "${n1} * ${m1}" | bc)
            if [[ ${LEN} -gt 24000 ]]; then
                continue
            fi
            compute_complexity ${LEN}

            ${POLGEN_BIN} -t beeline --n1 ${n1} --m1 ${m1} -o ${CONFIG}
            scp -q ${CONFIG} ${DEST_HOST}:${ROOT}/../../config/beeline/pc.yaml

            # check if beeline can compile this policy
            validate_policy
            if [[ $? -ne 0 ]]; then
                echo -e "${COLOR_YELLOW}Beeline failed to compile policy. Skipping${COLOR_OFF}"
                continue
            fi

            ${POLGEN_BIN} -t envoy --n1 ${n1} --m1 ${m1} -o ${CONFIG}
            scp -q ${CONFIG} ${DEST_HOST}:${ROOT}/../../config/envoy/pc.yaml

            PAYLOAD=$(eval "printf 'a%.0s' {1..$m1}")
            FRONTEND_ARGS=$(frontend_args $n1)

            script/bench.sh sm -e "PROXY_CONFIG=pc.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}/p1-n1-${n1}-m1-${m1} -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
            script/bench.sh sm -e "PROXY_CONFIG=pc.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}/p1-n1-${n1}-m1-${m1} -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
            script/bench.sh sm -e "PROXY_CONFIG=pc.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}/p1-n1-${n1}-m1-${m1} -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO}
        done
    done
fi

if [[ -z "${POLICY}" || ${POLICY} == "2" ]]; then
    echo Running policy 2

    for n1 in $(seq 1 10); do
        for m1 in $(seq 1000 1000 16000); do
            LEN=$(echo "${n1} * ${m1}" | bc)
            if [[ ${LEN} -gt 24000 ]]; then
                continue
            fi
            compute_complexity ${LEN}

            ${POLGEN_BIN} -t beeline --n1 ${n1} --m1 ${m1} --n2 ${n2} -o ${CONFIG}
            scp -q ${CONFIG} ${DEST_HOST}:${ROOT}/../../config/beeline/pc.yaml

            # check if beeline can compile this policy
            validate_policy
            if [[ $? -ne 0 ]]; then
                echo -e "${COLOR_YELLOW}Beeline failed to compile policy. Skipping${COLOR_OFF}"
                continue
            fi

            ${POLGEN_BIN} -t envoy --n1 ${n1} --m1 ${m1}  --n2 ${n2} -o ${CONFIG}
            scp -q ${CONFIG} ${DEST_HOST}:${ROOT}/../../config/envoy/pc.yaml

            PAYLOAD=$(eval "printf 'a%.0s' {1..$m1}")
            FRONTEND_ARGS=$(frontend_args $n1)

            script/bench.sh sm -e "PROXY_CONFIG=pc.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}/p2-n1-${n1}-m1-${m1}-n2-${n2} -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
            script/bench.sh sm -e "PROXY_CONFIG=pc.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}/p2-n1-${n1}-m1-${m1}-n2-${n2} -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
            script/bench.sh sm -e "PROXY_CONFIG=pc.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}/p2-n1-${n1}-m1-${m1}-n2-${n2} -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO}
        done
    done
fi

if [[ -z "${POLICY}" || ${POLICY} == "3" ]]; then
    echo Running policy 3

    for n1 in $(seq 1 10); do
        for m1 in $(seq 1000 1000 16000); do
            LEN=$(echo "${n1} * ${m1}" | bc)
            if [[ ${LEN} -gt 24000 ]]; then
                continue
            fi
            compute_complexity ${LEN}

            ${POLGEN_BIN} -t beeline --n1 ${n1} --m1 ${m1} --n2 ${n2} --n3 ${n3} --m3 ${m3} -o ${CONFIG}
            scp -q ${CONFIG} ${DEST_HOST}:${ROOT}/../../config/beeline/pc.yaml

            # check if beeline can compile this policy
            validate_policy
            if [[ $? -ne 0 ]]; then
                echo -e "${COLOR_YELLOW}Beeline failed to compile policy. Skipping${COLOR_OFF}"
                continue
            fi

            ${POLGEN_BIN} -t envoy --n1 ${n1} --m1 ${m1} --n2 ${n2} --n3 ${n3} --m3 ${m3} -o ${CONFIG}
            scp -q ${CONFIG} ${DEST_HOST}:${ROOT}/../../config/envoy/pc.yaml

            AUD=$(eval "printf 'a%.0s' {1..$n3}")
            ISS=$(eval "printf 'a%.0s' {1..$m3}")
            CLAIMS='{"iss":"'${ISS}'", "aud":"'${AUD}'"}'
            JWT=$(jwt encode --secret testtest12345678 "${CLAIMS}")

            PAYLOAD=$(eval "printf 'a%.0s' {1..$m1}")
            FRONTEND_ARGS=$(echo \'$(frontend_args $n1),Authorization: Bearer ${JWT}\')

            script/bench.sh sm -e "PROXY_CONFIG=pc.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}/p3-n1-${n1}-m1-${m1}-n2-${n2}-n3-${n3}-m3-${m3} -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
            script/bench.sh sm -e "PROXY_CONFIG=pc.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}/p3-n1-${n1}-m1-${m1}-n2-${n2}-n3-${n3}-m3-${m3} -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
            script/bench.sh sm -e "PROXY_CONFIG=pc.yaml REPLICAS=${REPLICAS} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}/p3-n1-${n1}-m1-${m1}-n2-${n2}-n3-${n3}-m3-${m3} -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO}
        done
    done
fi

if [[ -z "${POLICY}" || ${POLICY} == "4" ]]; then
    echo Running policy 4
    P4_REPLICAS=$(echo "3 * ${REPLICAS}" | bc)
    P4_SERVICES=${REPLICAS}

    for n1 in $(seq 1 10); do
        for m1 in $(seq 1000 1000 16000); do
            LEN=$(echo "${n1} * ${m1}" | bc)
            if [[ ${LEN} -gt 24000 ]]; then
                continue
            fi
            compute_complexity ${LEN}

            if [[ -f ${ROOT}/../../res/runs/${NAME}/p4-n1-${n1}-m1-${m1}-n2-${n2}-n3-${n3}-m3-${m3}-n4-${n4}/envoy-k6-e1-summary.json && -f ${ROOT}/../../res/runs/${NAME}/p4-n1-${n1}-m1-${m1}-n2-${n2}-n3-${n3}-m3-${m3}-n4-${n4}/envoy_l4fp-k6-e1-summary.json && -f ${ROOT}/../../res/runs/${NAME}/p4-n1-${n1}-m1-${m1}-n2-${n2}-n3-${n3}-m3-${m3}-n4-${n4}/beeline-k6-e1-summary.json ]]; then
                echo -e "${COLOR_GREEN}Found existing results${COLOR_OFF}"
                continue
            fi

            ${POLGEN_BIN} -t beeline --n1 ${n1} --m1 ${m1} --n2 ${n2} --n3 ${n3} --m3 ${m3} --n4 ${n4} -o ${CONFIG}
            scp -q ${CONFIG} ${DEST_HOST}:${ROOT}/../../config/beeline/pc.yaml

            # check if beeline can compile this policy
            validate_policy
            if [[ $? -ne 0 ]]; then
                echo -e "${COLOR_YELLOW}Beeline failed to compile policy. Skipping${COLOR_OFF}"
                continue
            fi

            ${POLGEN_BIN} -t envoy --n1 ${n1} --m1 ${m1} --n2 ${n2} --n3 ${n3} --m3 ${m3} --n4 ${n4} -o ${CONFIG}
            scp -q ${CONFIG} ${DEST_HOST}:${ROOT}/../../config/envoy/pc.yaml

            AUD=$(eval "printf 'a%.0s' {1..$n3}")
            ISS=$(eval "printf 'a%.0s' {1..$m3}")
            CLAIMS='{"iss":"'${ISS}'", "aud":"'${AUD}'"}'
            JWT=$(jwt encode --secret testtest12345678 "${CLAIMS}")

            PAYLOAD=$(eval "printf 'a%.0s' {1..$m1}")
            FRONTEND_ARGS=$(echo \'$(frontend_args $n1),Authorization: Bearer ${JWT}\')

            if [[ -f ${ROOT}/../../res/runs/${NAME}/p4-n1-${n1}-m1-${m1}-n2-${n2}-n3-${n3}-m3-${m3}-n4-${n4}/beeline-k6-e1-summary.json ]]; then
                echo "Beeline exists"
            else
                script/bench.sh sm -e "PROXY_CONFIG=pc.yaml REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-beeline.yaml -n ${NAME}/p4-n1-${n1}-m1-${m1}-n2-${n2}-n3-${n3}-m3-${m3}-n4-${n4} -p beeline -s ${SCRIPT} -f ${FROM} -t ${TO}
            fi

            if [[ -f ${ROOT}/../../res/runs/${NAME}/p4-n1-${n1}-m1-${m1}-n2-${n2}-n3-${n3}-m3-${m3}-n4-${n4}/envoy-k6-e1-summary.json ]]; then
                echo "Envoy exists"
            else
                script/bench.sh sm -e "PROXY_CONFIG=pc.yaml REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}/p4-n1-${n1}-m1-${m1}-n2-${n2}-n3-${n3}-m3-${m3}-n4-${n4} -p envoy -s ${SCRIPT} -f ${FROM} -t ${TO}
            fi

            if [[ -f ${ROOT}/../../res/runs/${NAME}/p4-n1-${n1}-m1-${m1}-n2-${n2}-n3-${n3}-m3-${m3}-n4-${n4}/envoy_l4fp-k6-e1-summary.json ]]; then
                echo "L4FP exists"
            else
                script/bench.sh sm -e "PROXY_CONFIG=pc.yaml REPLICAS=${P4_REPLICAS} SERVICES=${P4_SERVICES} FRONTEND_ARGS=${FRONTEND_ARGS}" -c docker/ssm-envoy.yaml -n ${NAME}/p4-n1-${n1}-m1-${m1}-n2-${n2}-n3-${n3}-m3-${m3}-n4-${n4} -p envoy_l4fp -s ${SCRIPT} -f ${FROM} -t ${TO}
            fi
        done
    done
fi
