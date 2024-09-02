trap "kill 0" SIGINT

envoy -c config.yaml