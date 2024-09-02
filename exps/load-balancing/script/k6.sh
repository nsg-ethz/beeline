#!/bin/bash

while getopts "n:p:s:" opt
do
   case "$opt" in
      n ) NAME=${OPTARG} ;;
      p ) PROXY=${OPTARG} ;;
      s ) SIZE=${OPTARG} ;;
   esac
done

if [ -z ${PROXY} ] || [ -z ${SIZE} ]
then
   echo "Some or all of the parameters are empty";
fi

CMD="PAYLOAD_SIZE=${SIZE} taskset --cpu-list 2-8 k6 run -o csv=res/${NAME}/logs/stress-${PROXY}-${SIZE}B.gz --summary-export=res/${NAME}/summary/stress-${PROXY}-${SIZE}B.json bench/stress.js"
echo ${CMD}
eval ${CMD}