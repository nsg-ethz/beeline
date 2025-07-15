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

script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/ms.yaml" -c docker/ms-beeline.yaml -n ${NAME} -p beeline -s k6/ms-compose-review.js -f ${FROM} -t ${TO} -r
script/bench.sh sm -c docker/ms-envoy.yaml -n ${NAME} -p envoy -s k6/ms-compose-review.js -f ${FROM} -t ${TO} -r
script/bench.sh sm -c docker/ms-envoy.yaml -n ${NAME} -p baseline -s k6/ms-compose-review.js -f ${FROM} -t ${TO} -r
script/bench.sh sm -c docker/ms-envoy-accelerated.yaml -n ${NAME} -p envoy -s k6/ms-compose-review.js -f ${FROM} -t ${TO} -r
