ROOT=$(dirname "$(readlink -f "$0")")
BACKEND="1"

# Parse arguments
while getopts "b:" opt; do
    case $opt in
        b ) BACKEND=${OPTARG} ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

curl -vvv -d @${ROOT}/../res/debug/payload-8192B.json http://10.0.5.1:3000/server${BACKEND}