#!/usr/bin/env bash
# Tests script/hot_restart: policy A denies DELETE, policy B denies PUT.
# Needs sudo and the crypto kernel module (see the README). Uses the ports 48100 and 48101.
set -euo pipefail

root=$(realpath "$(dirname "$0")/..")
tmp=$(mktemp -d)
proxy=127.0.0.1:48100
pids=()

cleanup() {
    for p in "${pids[@]}"; do sudo kill "$p" 2>/dev/null || true; done
    rm -rf "$tmp"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    for f in "$tmp"/*.log; do
        echo "--- $f" >&2
        tail -n 20 "$f" >&2
    done
    exit 1
}

config() {
    cat >"$tmp/$1.yaml" <<EOF
hosts:
    - name: server1
      instances:
          - 127.0.0.1:48101
routes:
    - match:
          path: "*"
      dest: server1
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

# an upstream that answers every method with 200 on keep-alive connections
cat >"$tmp/upstream.py" <<'EOF'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_one_request(self):
        self.raw_requestline = self.rfile.readline(65537)
        if not self.raw_requestline:
            self.close_connection = True
            return
        if not self.parse_request():
            return
        self.rfile.read(int(self.headers.get("content-length", 0)))
        self.send_response(200)
        self.send_header("content-length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
        self.wfile.flush()

ThreadingHTTPServer(("127.0.0.1", 48101), Handler).serve_forever()
EOF
python3 -I "$tmp/upstream.py" >"$tmp/upstream.log" 2>&1 &
pids+=($!)

# prints the status code, 000 if beeline drops the request
status() {
    curl -s -o /dev/null -w '%{http_code}' -m 2 -X "$1" "http://${proxy}/admin" || true
}

expect() {
    local got
    got=$(status "$1")
    [[ $got == "$2" ]] || fail "$1 on a new connection: expected $2, got $got ($3)"
}

# keeps one connection open. It reads a method per line and prints the status code, 000 if beeline drops the request
cat >"$tmp/client.py" <<'EOF'
import socket, sys

sock = socket.create_connection(sys.argv[1].split(":"), timeout=2)
res = sock.makefile("rb")
for method in sys.stdin:
    try:
        # one write, the data plane drops a request that is split over writes
        sock.sendall(f"{method.strip()} /admin HTTP/1.1\r\nHost: test\r\n\r\n".encode())
        code = res.readline().split()[1].decode()
        length = 0
        while line := res.readline().strip():
            name, _, value = line.decode().partition(":")
            if name.lower() == "content-length":
                length = int(value)
        res.read(length)
        print(code, flush=True)
    except Exception:
        print("000", flush=True)
EOF

status_open() {
    local code
    echo "$1" >&"${CLIENT[1]}"
    read -r -t 5 code <&"${CLIENT[0]}" || code=000
    echo "$code"
}

listener_pids() {
    sudo ss -Hltnp "sport = :${proxy##*:}" | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u
}

(cd "$root" && CONFIG="$tmp/a.yaml" cargo build -q -p beeline)
pidfile=$tmp/old.pid
touch "$pidfile"
sudo sh -c 'echo $$ > "$0"; exec "$@"' "$pidfile" env RUST_LOG=info \
    "$root/target/debug/beeline" --address "$proxy" --config "$tmp/a.yaml" --drain-time 30 \
    >"$tmp/old.log" 2>&1 &
for _ in $(seq 600); do
    [[ -s $pidfile ]] && listener_pids | grep -qx "$(cat "$pidfile")" && break
    sleep 0.1
done
old=$(cat "$pidfile")
pids+=("$old")

expect GET 200 "policy A"
expect PUT 200 "policy A"
expect DELETE 000 "policy A"

coproc CLIENT { python3 -I "$tmp/client.py" "$proxy"; }
pids+=("$CLIENT_PID")
[[ $(status_open GET) == 200 ]] || fail "GET on the open connection before the reload"

new=$(LOG="$tmp/new.log" "$root/script/hot_restart" "$old" "$tmp/b.yaml") || fail "hot_restart"
pids+=("$new")

[[ $(listener_pids) == "$new" ]] || fail "listeners after the reload: $(listener_pids | xargs)"
expect GET 200 "policy B"
expect DELETE 200 "policy B"
expect PUT 000 "policy B"

sudo kill -0 "$old" 2>/dev/null || fail "the old instance exited before its connection closed"
# policy B denies PUT, so this shows that the old instance still serves the open connection
[[ $(status_open PUT) == 200 ]] || fail "PUT on the open connection after the reload"

client_in=${CLIENT[1]}
exec {client_in}>&-
for _ in $(seq 50); do
    sudo kill -0 "$old" 2>/dev/null || break
    sleep 0.1
done
sudo kill -0 "$old" 2>/dev/null && fail "the old instance does not exit after its last connection closed"

echo "PASS"
