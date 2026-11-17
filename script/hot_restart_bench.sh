#!/usr/bin/env bash
# Measures how long an HTTP/2 connection takes to migrate to a hot restarted beeline with a new policy.
#
# Every run starts the client of the hot_restart package on an instance with one policy and hot
# restarts beeline with the other one. The new instance tells the old one to drain, whose control
# plane sends GOAWAY on its HTTP/2 downstream connections. The client finishes the request in
# flight, closes the connection and reconnects, which lands on the new instance. Policy A denies
# DELETE, policy B denies PUT, the runs alternate between A -> B and B -> A. On the old connection,
# the client sends the method that the new policy denies. On the new one, it sends the method that
# the old policy denies, its response shows that the new policy applies. Both versions of beeline
# are built before the first run, so no hot restart compiles.
#
# Usage: script/hot_restart_bench.sh [-n NAME] [-r RUNS] [-i INTERVAL_MS] [-d]
#   -n  the experiment name, the results go to res/runs/NAME (default: hot_restart)
#   -r  the number of hot restarts (default: 10)
#   -i  the time the client waits between two requests on the old connection (default: 10)
#   -d  use a debug build of beeline instead of a release build
#
# Writes res/runs/NAME/hot_restart.csv, all durations in ms, and the logs of every instance
# to res/runs/NAME/logs:
#   script              hot_restart.sh starts -> it starts the new instance, not part of total. Mostly
#                       sudo, which hot_restart.sh needs to read the old instance from /proc
#   exec_to_listen      hot_restart.sh starts the new instance -> it listens
#   startup             main of the new instance -> it listens (the instance logs it)
#   listen_to_drain     new instance listens -> old instance drains, which sends GOAWAY
#   drain_to_goaway     old instance drains -> client receives GOAWAY
#   goaway_to_close     client receives GOAWAY -> client closes the old connection
#   close_to_connect    client closes the old connection -> new connection is established
#   connect_to_response new connection is established -> first response under the new policy
#   goaway_to_response  client receives GOAWAY -> first response under the new policy
#   total               hot_restart.sh starts the new instance -> first response under the new policy
#   gap                 last response on the old connection -> first one on the new connection
#   latency             median latency of a request on the old connection. A request in flight
#                       when the GOAWAY arrives finishes before the client closes the connection
#
# Needs sudo and the crypto kernel module (see the README). Uses 127.0.0.1:48110 and 127.0.0.2:48111.
set -euo pipefail

name=hot_restart
runs=10
interval=10
profile=release
while getopts "n:r:i:d" opt; do
    case $opt in
    n) name=$OPTARG ;;
    r) runs=$OPTARG ;;
    i) interval=$OPTARG ;;
    d) profile=debug ;;
    *)
        sed -n 's/^# \{0,1\}//; 13,17p' "$0" >&2
        exit 1
        ;;
    esac
done

root=$(realpath "$(dirname "$0")/..")
out=$root/res/runs/$name
csv=$out/hot_restart.csv
tmp=$(mktemp -d)
proxy=127.0.0.1:48110
# beeline picks HTTP/2 for a downstream connection whose client IP is that of an HTTP/2 host
backend=127.0.0.2:48111
client_ip=127.0.0.2
drain_time=30
pids=()

# the data plane logs at the level of the build environment, which slows it down
unset RUST_LOG BPF_LOG BPF_PROFILE
build=(cargo build -q -p beeline)
[[ $profile == release ]] && build+=(--release)

rm -rf "$out/logs"
mkdir -p "$out/logs"

listener_pids() {
    sudo ss -Hltnp "sport = :${proxy##*:}" | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u
}

cleanup() {
    # a hot restart that fails can leave an instance behind whose pid it did not print
    for p in "${pids[@]}" $(listener_pids); do sudo kill "$p" 2>/dev/null || true; done
    rm -rf "$tmp"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    for f in "$tmp"/*.out "$out"/logs/*.log; do
        [[ -s $f ]] || continue
        echo "--- $f" >&2
        tail -n 20 "$f" >&2
    done
    exit 1
}

config() {
    cat >"$tmp/$1.yaml" <<EOF
hosts:
    - name: h2-server
      http2: true
      instances:
          - ${backend}
routes:
    - match:
          path: "*"
      dest: h2-server
policies:
    - name: deny-$2
      method: $2
      allow: false
    - name: allow-rest
      allow: true
EOF
}
config a DELETE
config b PUT
declare -A denies=([a]=DELETE [b]=PUT)

# turns the start of the hot restart, the start of the new instance, the client's output and the
# logs of both instances into a CSV row
cat >"$tmp/row.py" <<'EOF'
import calendar, datetime, json, re, sys

client, old_log, new_log, run, src, dst, restarted, started = sys.argv[1:9]
restarted, started = int(restarted), int(open(started).read())


def logged(log, needle):
    """The timestamp in ns of the first line that contains needle, and the line."""
    for line in open(log, errors="replace"):
        line = re.sub(r"\x1b\[[0-9;]*m", "", line)
        if needle in line:
            # tracing logs the UTC time, e.g. 2026-11-17T10:00:00.123456Z
            t = datetime.datetime.fromisoformat(line.split()[0])
            return calendar.timegm(t.utctimetuple()) * 10**9 + t.microsecond * 1000, line
    sys.exit(f"{log} does not log '{needle}'")


c = json.loads(open(client).read().splitlines()[-1])
listen, line = logged(new_log, "Listening on")
startup = float(re.search(r"in (\d+)ms", line).group(1))
drain, _ = logged(old_log, "Draining")

ms = lambda a, b: (b - a) / 1e6
durations = [
    ms(restarted, started),
    ms(started, listen),
    startup,
    ms(listen, drain),
    ms(drain, c["goaway_at"]),
    c["goaway_to_close"],
    c["close_to_connect"],
    c["connect_to_response"],
    c["goaway_to_response"],
    ms(started, c["answered_at"]),
    c["gap"],
    c["latency"],
]
counts = [c["requests"], c["failed"], c["goaway_last_stream"], c["goaway_code"]]
print(",".join([run, src, dst] + [f"{d:.3f}" for d in durations] + [str(n) for n in counts]))
EOF

cat >"$tmp/stats.py" <<'EOF'
import csv, statistics, sys

rows = list(csv.DictReader(open(sys.argv[1])))
cols = ["script", "exec_to_listen", "startup", "listen_to_drain", "drain_to_goaway",
        "goaway_to_close", "close_to_connect", "connect_to_response", "goaway_to_response",
        "total", "gap", "latency"]
print(f"{'(ms, ' + str(len(rows)) + ' runs)':<22} {'median':>10} {'mean':>10} {'min':>10} {'max':>10}")
for col in cols:
    v = [float(r[col]) for r in rows]
    print(f"{col:<22} {statistics.median(v):>10.3f} {statistics.mean(v):>10.3f} {min(v):>10.3f} {max(v):>10.3f}")
EOF

echo "Building the client and the backend"
# the client's timestamps are part of the measurement, so both are always optimized
(cd "$root" && cargo build -q -p hot_restart --release)

# beeline forwards the requests of the client to it
"$root/target/release/backend" "$backend" >"$out/logs/backend.log" 2>&1 &
pids+=($!)

# the data plane is compiled for the config, so every policy has a binary of its own
for policy in a b; do
    echo "Building beeline (${profile}) for policy ${policy^^}"
    (cd "$root" && CONFIG="$tmp/$policy.yaml" "${build[@]}")
    # hot_restart.sh checks that the binary is called beeline
    mkdir "$tmp/$policy"
    cp "$root/target/$profile/beeline" "$tmp/$policy/beeline"
done

cur=a
cur_log=$out/logs/0-a.log
pidfile=$tmp/beeline.pid
touch "$pidfile"
sudo sh -c 'echo $$ > "$0"; exec "$@"' "$pidfile" env RUST_LOG=info NO_COLOR=1 \
    "$tmp/a/beeline" --address "$proxy" --config "$tmp/a.yaml" --drain-time "$drain_time" \
    >"$cur_log" 2>&1 &
for _ in $(seq 600); do
    [[ -s $pidfile ]] && listener_pids | grep -qx "$(cat "$pidfile")" && break
    sleep 0.1
done
cur_pid=$(cat "$pidfile")
pids+=("$cur_pid")
[[ $(listener_pids) == "$cur_pid" ]] || fail "beeline with policy A does not listen on ${proxy}"

echo "run,from,to,script,exec_to_listen,startup,listen_to_drain,drain_to_goaway,goaway_to_close,close_to_connect,connect_to_response,goaway_to_response,total,gap,latency,requests,failed,goaway_last_stream,goaway_code" >"$csv"

for run in $(seq "$runs"); do
    next=$([[ $cur == a ]] && echo b || echo a)
    next_log=$out/logs/$run-$next.log

    client_out=$tmp/client-$run.out
    "$root/target/release/client" "$proxy" "$client_ip" "${denies[$next]}" "${denies[$cur]}" \
        --interval "$interval" --wait 60 >"$client_out" 2>&1 &
    client=$!
    pids+=("$client")
    for _ in $(seq 100); do
        grep -qx ready "$client_out" 2>/dev/null && break
        kill -0 "$client" 2>/dev/null || break
        sleep 0.1
    done
    grep -qx ready "$client_out" || fail "run ${run}: the client does not get a response from policy ${cur^^}"

    # root writes the start of the new instance into it, which keeps the owner of a file that exists
    started=$tmp/started-$run
    touch "$started"
    restarted=$(date +%s%N)
    new_pid=$(LOG="$next_log" STARTED="$started" "$root/script/hot_restart.sh" "$cur_pid" "$tmp/$next.yaml" "$tmp/$next/beeline") ||
        fail "run ${run}: hot restart to policy ${next^^}"
    pids+=("$new_pid")

    wait "$client" || fail "run ${run}: the client did not reconnect to policy ${next^^}"

    # the old instance exits once the client closed its connection
    for _ in $(seq $((drain_time * 10 + 50))); do
        sudo kill -0 "$cur_pid" 2>/dev/null || break
        sleep 0.1
    done
    sudo kill -0 "$cur_pid" 2>/dev/null && fail "run ${run}: the old instance does not exit"

    row=$(python3 -I "$tmp/row.py" "$client_out" "$cur_log" "$next_log" "$run" "${cur^^}" "${next^^}" \
        "$restarted" "$started") || fail "run ${run}: no timestamps"
    echo "$row" >>"$csv"
    echo "run ${run} (${cur^^} -> ${next^^}): $(cut -d, -f13 <<<"$row")ms from the start of the new instance," \
        "$(cut -d, -f12 <<<"$row")ms from GOAWAY to the first response under policy ${next^^}"

    cur=$next
    cur_pid=$new_pid
    cur_log=$next_log
done

echo
python3 -I "$tmp/stats.py" "$csv"
echo "Results in ${csv}"
