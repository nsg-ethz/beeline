trap "kill 0" SIGINT

taskset --cpu-list 1 envoy -c config.yaml --concurrency 1