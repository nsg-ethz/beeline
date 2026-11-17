#!/usr/bin/env bash
# Replaces a running beeline with one that is built for a new config.
# The new instance gets all new connections, the old one drains its open connections and exits.
#
# Usage: script/hot_restart.sh <pid> <config> [binary]
# Builds beeline for the config and runs it from the path of the old instance, unless binary
# names one that is built for the config already.
# Prints the pid of the new instance. LOG sets its log file. STARTED names a file that gets the time
# in ns since the epoch right before the new instance starts, the caller creates it to be able to read it.
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "Usage: $0 <pid> <config> [binary]" >&2
    exit 1
fi

pid=$1
config=$(realpath "$2")
root=$(realpath "$(dirname "$0")/..")

exe=$(sudo readlink "/proc/${pid}/exe")
# a previous hot reload replaced the binary of the old instance
exe=${exe% (deleted)}
if [[ $(basename "$exe") != beeline ]]; then
    echo "${pid} is not a beeline process" >&2
    exit 1
fi
cwd=$(sudo readlink "/proc/${pid}/cwd")
mapfile -d '' envs < <(sudo cat "/proc/${pid}/environ")

# the new instance runs with the arguments of the old one, except the config
args=()
skip=0
while IFS= read -r -d '' arg; do
    if ((skip)); then
        skip=0
        continue
    fi
    case $arg in
    -c | --config | --replace) skip=1 ;;
    --config=* | --replace=*) ;;
    *) args+=("$arg") ;;
    esac
done < <(sudo tail -z -n +2 "/proc/${pid}/cmdline")

if [[ $# -eq 3 ]]; then
    exe=$(realpath "$3")
else
    profile=()
    [[ $exe == */release/* ]] && profile=(--release)
    # the data plane is compiled for the config
    (cd "$root" && CONFIG=$config cargo build -q -p beeline "${profile[@]}")
fi

# without it, the kernel resets the connections in the accept queue of the old listener
sudo sysctl -qw net.ipv4.tcp_migrate_req=1

log=${LOG:-$(mktemp /tmp/beeline.XXXXXX.log)}
# in a directory of its own, root cannot write to a file of another user in /tmp (fs.protected_regular)
piddir=$(mktemp -d)
pidfile=$piddir/pid
# the whole subshell goes to the log, so that nothing holds the stdout of a caller that reads the pid
(cd "$cwd" && exec sudo sh -c 'echo $$ > "$0"; [ -n "$1" ] && date +%s%N > "$1"; shift; exec "$@"' \
    "$pidfile" "${STARTED:-}" env -i "${envs[@]}" "$exe" "${args[@]}" --config "$config" --replace "$pid") \
    </dev/null >"$log" 2>&1 &

new=""
for _ in $(seq 1200); do
    # root writes it with its umask, which can keep it from other users
    new=$(sudo cat "$pidfile" 2>/dev/null || true)
    if [[ -n $new ]] && sudo ss -Hltnp | grep -q "pid=${new},"; then
        rm -rf "$piddir"
        echo "$new"
        exit 0
    fi
    if [[ -n $new ]] && ! sudo kill -0 "$new" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

rm -rf "$piddir"
echo "The new beeline does not listen, see ${log}:" >&2
tail -n 20 "$log" >&2
exit 1
