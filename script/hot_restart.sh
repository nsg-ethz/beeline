#!/usr/bin/env bash
# Replaces a running beeline with one that is built for a new config.
# The new instance gets all new connections, the old one drains its open connections and exits.
#
# Usage: script/hot_restart <pid> <config>
# Prints the pid of the new instance. LOG sets its log file.
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <pid> <config>" >&2
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

profile=()
[[ $exe == */release/* ]] && profile=(--release)
# the data plane is compiled for the config
(cd "$root" && CONFIG=$config cargo build -q -p beeline "${profile[@]}")

# without it, the kernel resets the connections in the accept queue of the old listener
sudo sysctl -qw net.ipv4.tcp_migrate_req=1

log=${LOG:-$(mktemp /tmp/beeline.XXXXXX.log)}
pidfile=$(mktemp)
(cd "$cwd" && sudo sh -c 'echo $$ > "$0"; exec "$@"' "$pidfile" \
    env -i "${envs[@]}" "$exe" "${args[@]}" --config "$config" --replace "$pid" \
    >"$log" 2>&1 &)

new=""
for _ in $(seq 1200); do
    new=$(cat "$pidfile")
    if [[ -n $new ]] && sudo ss -Hltnp | grep -q "pid=${new},"; then
        rm "$pidfile"
        echo "$new"
        exit 0
    fi
    if [[ -n $new ]] && ! sudo kill -0 "$new" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

rm "$pidfile"
echo "The new beeline does not listen, see ${log}:" >&2
tail -n 20 "$log" >&2
exit 1
