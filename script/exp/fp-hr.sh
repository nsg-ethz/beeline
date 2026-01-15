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

script/bench.sh sm -e "PROXY_CONFIG=hr.yaml" -c docker/hr-beeline.yaml -n ${NAME} -p beeline -s k6/hr.js -f ${FROM} -t ${TO} -r
script/bench.sh sm -e "PROXY_CONFIG=hr.yaml" -c docker/hr-envoy.yaml -n ${NAME} -p envoy -s k6/hr.js -f ${FROM} -t ${TO} -r
script/bench.sh sm -e "PROXY_CONFIG=hr.yaml" -c docker/hr-envoy.yaml -n ${NAME} -p envoy_l4fp -s k6/hr.js -f ${FROM} -t ${TO} -r
