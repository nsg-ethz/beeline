ROOT=$(dirname "$(readlink -f "$0")")

curl -vvv -d @${ROOT}/../res/debug/payload-8192B.json http://10.0.5.1:3000/server1