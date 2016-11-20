#!/bin/bash
curl https://sh.rustup.rs -sSf | sh
. $HOME/.cargo/env
git clone https://github.com/loggerhead/shadowsocks-rust.git && cd shadowsocks-rust/
cargo build --release --features "$SS_FEATURES" && mv target/release/ssserver ssserver
cargo build --release --features "sslocal $SS_FEATURES" && mv target/release/ssserver sslocal
./ssserver --version
./sslocal --version
