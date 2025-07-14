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

script/bench.sh sm -e "BEELINE_CONFIG=config/beeline/sn.yaml" -c docker/sn-beeline.yaml -n ${NAME} -p beeline -s k6/sn-compose-post.js -f ${FROM} -t ${TO} -r
script/bench.sh sm -c docker/sn-envoy.yaml -n ${NAME} -p envoy -s k6/sn-compose-post.js -f ${FROM} -t ${TO} -r
script/bench.sh sm -c docker/sn-envoy-accelerated.yaml -n ${NAME} -p baseline -s k6/sn-compose-post.js -f ${FROM} -t ${TO} -r
