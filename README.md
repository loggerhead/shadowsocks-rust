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

#TODO
- [x] add cache for DNS
- [x] review `unwrap`, `.ok()`、`unimplemented`, `unreachable`
- [x] check if there exists `cannot decrypt` log
- [x] test with shadowsocks
- [x] remove unnecessary `clone` ~~(maybe this is the cause of high CPU problem)~~
- [x] find the reason of high CPU (5% ~ 20%)
- [x] ~~fix high CPU caused by `on_remote_read`~~ (see issue [#1](https://github.com/loggerhead/shadowsocks-rust/issues/1))
- [ ] ~~response slow after fixed high CPU problem~~
- [ ] finish all TODO items in source (wait `cargo` to support `required-feature`, see [pull 2056](https://github.com/rust-lang/cargo/pull/2056))
- [x] handle the timeout situation of client
- [x] handle DNS error properly (e.g. remove caller or call `resolve` again)
- [x] review `tcp_processor`
- [x] ~~refactor error handle~~

#Features need to finished
- [x] Running as daemon
- [x] UDP support
- [x] OTA encrypt method support
- [ ] Multiple encrypt methods support
- [ ] TCP fast open (wait a new computer)

#Test sites
* http://www.bilibili.com/
* http://www.panda.tv/
