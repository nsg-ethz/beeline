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

script/bench.sh sm -e "PROXY_CONFIG=ms.yaml" -c docker/ms-beeline.yaml -n ${NAME} -p beeline -s k6/ms-compose-review.js -f ${FROM} -t ${TO} -r
script/bench.sh sm -c docker/ms-envoy.yaml -n ${NAME} -p envoy -s k6/ms-compose-review.js -f ${FROM} -t ${TO} -r
script/bench.sh sm -c docker/ms-envoy.yaml -n ${NAME} -p envoy_l4fp -s k6/ms-compose-review.js -f ${FROM} -t ${TO} -r
script/bench.sh sm -c docker/ms-envoy-accelerated.yaml -n ${NAME} -p envoy_iouring -s k6/ms-compose-review.js -f ${FROM} -t ${TO} -r
