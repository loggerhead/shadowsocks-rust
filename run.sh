#!/bin/bash
PROXY_PORT=8010
RUST_BACKTRACE=1

if [[ "$1" == "ps" ]]; then
    cpid=$(lsof -i :$PROXY_PORT | grep LISTEN | awk '{ print $2 }')
    spid=$(lsof -i :8111 | grep LISTEN | awk '{ print $2 }')
    sudo htop -p $cpid -p $spid
elif [[ "$1" == "r" ]]; then
    curl --socks5 127.0.0.1:$PROXY_PORT http://localhost:8001/
elif [[ "$1" == "rs" ]]; then
    python -m SimpleHTTPServer 8001
elif [[ "$1" == "c" ]]; then
    shift
    cargo run --features sslocal -- -c tests/config/client_conf.toml $@
elif [[ "$1" == "s" ]]; then
    shift
    cargo run -- -c tests/config/server_conf.toml $@
elif [[ "$1" == "check" ]]; then
    rustup default nightly
    cargo build --features clippy
    rustup default stable
fi
