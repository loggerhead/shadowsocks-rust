#!/bin/bash
if [[ "$1" == "r" ]]; then
    nc -X 5 -x 127.0.0.1:8488 localhost 8001
elif [[ "$1" == "rs" ]]; then
    python -m SimpleHTTPServer 8001
else
    RUST_BACKTRACE=1 RUST_LOG=shadowsocks=debug cargo run --bin $@
fi
