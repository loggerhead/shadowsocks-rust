#shadowsocks-rust
[![Build Status](https://travis-ci.org/loggerhead/shadowsocks-rust.svg?branch=master)](https://travis-ci.org/loggerhead/shadowsocks-rust)
[![Build status](https://ci.appveyor.com/api/projects/status/ti4hi7era48ltxq4?svg=true)](https://ci.appveyor.com/project/loggerhead/shadowsocks-rust)

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
- [ ] fix high CPU caused by `on_remote_read`
- [ ] ~~response slow after fixed high CPU problem~~
- [ ] finish all TODO items in source
- [x] handle the timeout situation of client
- [ ] handle DNS error properly (e.g. remove caller or call `resolve` again)
- [ ] review `tcp_processor`
- [ ] refactor error handle

#Features need to finished
- [ ] Running as daemon
- [ ] UDP support
- [ ] OTA encrypt method support
- [ ] TCP fast open
- [ ] Multiple encrypt methods support

#Test sites
* http://www.bilibili.com/
* http://www.panda.tv/
