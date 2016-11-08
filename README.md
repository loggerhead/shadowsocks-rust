#shadowsocks-rust
[![Build Status](https://travis-ci.org/loggerhead/shadowsocks-rust.svg?branch=master)](https://travis-ci.org/loggerhead/shadowsocks-rust)
[![Build status](https://ci.appveyor.com/api/projects/status/ti4hi7era48ltxq4?svg=true)](https://ci.appveyor.com/project/loggerhead/shadowsocks-rust)
[![crate](https://img.shields.io/crates/v/shadowsocks.svg)](https://crates.io/crates/shadowsocks)

#Running
```bash
# start ssserver
./run.sh s
# start sslocal
./run.sh c
```

#Features
- [x] Running as daemon
- [x] UDP support
- [x] OTA encrypt method support
- [x] add mode support (`fast` and `balance`)
- [ ] Multiple encrypt methods support (wait a stable crypto library)
- [ ] TCP fast open (wait `mio` support)

#TBD
- [ ] test compatible with win10
- [ ] test IPv6
- [ ] bench with fast mode
