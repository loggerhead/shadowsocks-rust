#!/bin/bash
PROXY_PORT=8010
if [[ "$1" == "ps" ]]; then
    pids=$(ps | grep shadowsocks-rust | grep  target | awk '{ print $1 }')
    cmd="sudo htop"
    for p in $pids; do
        cmd=$(echo "$cmd -p $p")
    done
    eval $cmd
elif [[ "$1" == "r" ]]; then
    nc -X 5 -x 127.0.0.1:$PROXY_PORT localhost 8001
elif [[ "$1" == "rs" ]]; then
    python -m SimpleHTTPServer 8001
elif [[ "$1" == "c" ]]; then
    RUST_BACKTRACE=1 RUST_LOG=shadowsocks=trace cargo run --features is_client
elif [[ "$1" == "s" ]]; then
    RUST_BACKTRACE=1 RUST_LOG=shadowsocks=trace cargo run
fi
