trap "kill 0" SIGINT

ROOT=$(dirname "$(readlink -f "$0")")

taskset --cpu-list 1 envoy -c ${ROOT}/config.yaml --concurrency 1