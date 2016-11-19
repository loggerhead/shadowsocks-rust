# shadowsocks-rust
[![Build Status](https://travis-ci.org/loggerhead/shadowsocks-rust.svg?branch=master)](https://travis-ci.org/loggerhead/shadowsocks-rust)
[![Build status](https://ci.appveyor.com/api/projects/status/ti4hi7era48ltxq4?svg=true)](https://ci.appveyor.com/project/loggerhead/shadowsocks-rust)
[![crate](https://img.shields.io/crates/v/shadowsocks.svg)](https://crates.io/crates/shadowsocks)

A [rust](https://www.rust-lang.org) port of shadowsocks, based on [mio 0.5.x](https://crates.io/crates/mio).

# Install
## Without OpenSSL
```bash
curl https://raw.githubusercontent.com/loggerhead/shadowsocks-rust/master/install.sh -sSf | sh
```

## With OpenSSL
```bash
export SS_FEATURES=openssl
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

## Both Supported Encryption Methods

* AES-128-CTR
* AES-192-CTR
* AES-256-CTR
* AES-128-CFB
* AES-256-CFB
* AES-128-CFB1
* AES-256-CFB1
* AES-128-CFB8
* AES-256-CFB8
* Salsa20
* Chacha20
* RC4

# TBD
- [ ] test IPv6
- [ ] fix compatible problem on windows
- [ ] support TCP fast open
