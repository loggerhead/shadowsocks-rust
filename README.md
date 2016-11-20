# shadowsocks-rust
[![Build Status](https://travis-ci.org/loggerhead/shadowsocks-rust.svg?branch=master)](https://travis-ci.org/loggerhead/shadowsocks-rust)
[![Build status](https://ci.appveyor.com/api/projects/status/ti4hi7era48ltxq4?svg=true)](https://ci.appveyor.com/project/loggerhead/shadowsocks-rust)
[![crate](https://img.shields.io/crates/v/shadowsocks.svg)](https://crates.io/crates/shadowsocks)

A [rust](https://www.rust-lang.org) port of shadowsocks, based on [mio 0.5.x](https://crates.io/crates/mio).

# Install
```bash
# uncomment to compile with OpenSSL support
# export SS_FEATURES=openssl
curl https://raw.githubusercontent.com/loggerhead/shadowsocks-rust/master/install.sh -sSf | sh
```

# Compare to Python Version
## Features

|                             |        Rust        |      Python (2.9.0)      |
| --------------------------- | :----------------: | :----------------------: |
| TCP & UDP support           |       __√__        |          __√__           |
| TCP fast open               | wait `mio` support |          __√__           |
| Destination IP blacklist    |       __X__        |          __√__           |
| One time auth               |       __√__        |          __√__           |
| Multiple encryption methods |       __√__        |          __√__           |
| Async UDP support           |       __√__        |          __X__           |
| IPv6 support                |      untested      |          __X__           |
| Windows compatible          | wait `mio` stable  | need install crypto libs |
| Multiple servers support    |       __√__        |          __X__           |

# Encryption Methods
## Both python and rust version supported

* aes-128-ctr
* aes-192-ctr
* aes-256-ctr
* aes-128-cfb
* aes-256-cfb
* aes-128-cfb1
* aes-256-cfb1
* aes-128-cfb8
* aes-256-cfb8
* salsa20
* chacha20
* rc4

## Without OpenSSL
* aes-128-ctr
* aes-192-ctr
* aes-256-ctr
* rc4
* hc128
* salsa20
* xsalsa20
* chacha20
* xchacha20
* sosemanuk

# TBD
- [ ] test IPv6
- [ ] fix compatible problem on windows
- [ ] support TCP fast open
