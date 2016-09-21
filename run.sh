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
    RUST_BACKTRACE=1 RUST_LOG=shadowsocks=trace cargo run --features is_client 2>&1 | tee client.log
elif [[ "$1" == "s" ]]; then
    RUST_BACKTRACE=1 RUST_LOG=shadowsocks=trace cargo run 2>&1 | tee server.log
fi
