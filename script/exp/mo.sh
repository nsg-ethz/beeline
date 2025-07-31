#!/bin/bash

# Parse arguments
while getopts "f:t:n:" opt; do
    case $opt in
        f ) FROM=${OPTARG} ;;
        t ) TO=${OPTARG} ;;
        n ) NAME=${OPTARG} ;;

        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

script/bench.sh sm -e "PROXY_CONFIG=ms.yaml" -c docker/ms-beeline.yaml -n ${NAME} -p beeline -s k6/ms-compose-review-rps.js -f ${FROM} -t ${TO}
script/bench.sh sm -e "ENVOY_CONCURRENCY=1 PROXY_CONFIG=ms.yaml" -c docker/ms-envoy.yaml -n ${NAME} -p envoy -s k6/ms-compose-review-rps.js -f ${FROM} -t ${TO}
script/bench.sh sm -e "ENVOY_CONCURRENCY=1 PROXY_CONFIG=ms.yaml" -c docker/ms-envoy.yaml -n ${NAME} -p envoy_l4fp -s k6/ms-compose-review-rps.js -f ${FROM} -t ${TO}
script/bench.sh sm -e "PROXY_CONFIG=ms.yaml" -c docker/ms-vanilla.yaml -n ${NAME} -p none -s k6/ms-compose-review-rps.js -f ${FROM} -t ${TO}

script/bench.sh sm -e "PROXY_CONFIG=ms.yaml" -c docker/ms-beeline.yaml -n ${NAME}-bpf -p beeline -s k6/ms-compose-review-rps.js -f ${FROM} -t ${TO} -m 1
script/bench.sh sm -e "ENVOY_CONCURRENCY=1  PROXY_CONFIG=ms.yaml" -c docker/ms-envoy.yaml -n ${NAME}-bpf -p envoy -s k6/ms-compose-review-rps.js -f ${FROM} -t ${TO} -m 1
script/bench.sh sm -e "ENVOY_CONCURRENCY=1  PROXY_CONFIG=ms.yaml" -c docker/ms-envoy.yaml -n ${NAME}-bpf -p envoy_l4fp -s k6/ms-compose-review-rps.js -f ${FROM} -t ${TO} -m 1
