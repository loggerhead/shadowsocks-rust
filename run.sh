#!/bin/bash
PROXY_PORT=8010
if [[ "$1" == "ps" ]]; then
    cpid=$(lsof -i :$PROXY_PORT | grep LISTEN | awk '{ print $2 }')
    spid=$(lsof -i :8111 | grep LISTEN | awk '{ print $2 }')
    sudo htop -p $cpid -p $spid
elif [[ "$1" == "r" ]]; then
    nc -X 5 -x 127.0.0.1:$PROXY_PORT localhost 8001
elif [[ "$1" == "rs" ]]; then
    python -m SimpleHTTPServer 8001
elif [[ "$1" == "c" ]]; then
    shift
    RUST_BACKTRACE=1 cargo run --features is_client -- -c tests/config/client_conf.toml $@
elif [[ "$1" == "s" ]]; then
    shift
    RUST_BACKTRACE=1 cargo run -- -c tests/config/server_conf.toml $@
fi
