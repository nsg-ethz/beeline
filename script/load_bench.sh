#!/usr/bin/env bash
# Measures how long beeline takes from main until it listens.
#
# Builds beeline (release) once for the config, then starts it ITERATIONS times. Every instance
# logs "Listening on <addr>, in <duration>ms", which is recorded before the instance is stopped.
# Prints the average duration at the end.
#
# Usage: script/load_bench.sh -c CONFIG [-i ITERATIONS]
#   -c  the beeline config, the data plane is compiled for it
#   -i  the number of times beeline is started (default: 10)
#
# Needs sudo and the crypto kernel module (see the README).
set -euo pipefail

usage() {
    sed -n 's/^# \{0,1\}//; 8,10p' "$0" >&2
    exit 1
}

config=""
iterations=10
while getopts "c:i:" opt; do
    case $opt in
    c) config=$OPTARG ;;
    i) iterations=$OPTARG ;;
    *) usage ;;
    esac
done
[[ -n $config ]] || usage
[[ $iterations =~ ^[1-9][0-9]*$ ]] || usage

config=$(realpath "$config")
root=$(realpath "$(dirname "$0")/..")
bin=$root/target/release/beeline
tmp=$(mktemp -d)
pid=""

cleanup() {
    [[ -n $pid ]] && sudo kill "$pid" 2>/dev/null || true
    rm -rf "$tmp"
}
trap cleanup EXIT

# the data plane logs at the level of the build environment, which slows it down
unset RUST_LOG BPF_LOG BPF_PROFILE

echo "Building beeline for $(basename "$config")"
(cd "$root" && CONFIG=$config cargo build -q -p beeline --release)

durations=()
for run in $(seq "$iterations"); do
    log=$tmp/$run.log
    # in a directory of its own, root cannot write to a file of another user in /tmp (fs.protected_regular)
    pidfile=$tmp/pid-$run/pid
    mkdir "$tmp/pid-$run"
    (cd "$root" && exec sudo sh -c 'echo $$ > "$0"; exec "$@"' "$pidfile" \
        env RUST_LOG=info NO_COLOR=1 "$bin" --config "$config") </dev/null >"$log" 2>&1 &
    sudo_pid=$!

    line=""
    for _ in $(seq 1200); do
        line=$(grep -m1 "Listening on" "$log" || true)
        [[ -n $line ]] && break
        kill -0 "$sudo_pid" 2>/dev/null || break
        sleep 0.1
    done
    pid=$(sudo cat "$pidfile" 2>/dev/null || true)
    if [[ -z $line ]]; then
        echo "run ${run}: beeline does not listen, see the log:" >&2
        tail -n 20 "$log" >&2
        exit 1
    fi

    ms=$(sed -E 's/.*Listening on .*, in ([0-9]+)ms.*/\1/' <<<"$line")
    durations+=("$ms")
    echo "run ${run}: ${ms}ms"

    # SIGINT shuts it down cleanly, which unpins its maps before the next instance attaches
    sudo kill -INT "$pid"
    wait "$sudo_pid" || true
    pid=""
done

printf '%s\n' "${durations[@]}" |
    awk -v n="$iterations" '{ s += $1 } END { printf "\naverage over %d runs: %.2fms\n", n, s / n }'
