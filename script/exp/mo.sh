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

script/bench.sh sm -e "PROXY_CONFIG=sn-mo.yaml" -c docker/sn-beeline.yaml -n ${NAME} -p beeline -s k6/sn-rps.js -f ${FROM} -t ${TO}
script/bench.sh sm -e "PROXY_CONFIG=sn-mo.yaml" -c docker/sn-envoy.yaml -n ${NAME} -p envoy -s k6/sn-rps.js -f ${FROM} -t ${TO}
script/bench.sh sm -e "PROXY_CONFIG=sn-mo.yaml" -c docker/sn-envoy.yaml -n ${NAME} -p envoy_l4fp -s k6/sn-rps.js -f ${FROM} -t ${TO}
script/bench.sh sm -e "PROXY_CONFIG=sn-mo.yaml" -c docker/sn-vanilla.yaml -n ${NAME} -p none -s k6/sn-rps.js -f ${FROM} -t ${TO}
