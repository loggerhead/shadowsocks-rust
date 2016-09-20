#shadowsocks-rust
[![Build Status](https://travis-ci.org/loggerhead/shadowsocks-rust.svg?branch=master)](https://travis-ci.org/loggerhead/shadowsocks-rust)
[![Build status](https://ci.appveyor.com/api/projects/status/ti4hi7era48ltxq4?svg=true)](https://ci.appveyor.com/project/loggerhead/shadowsocks-rust)


#TODO

- [x] add cache for DNS
- [x] review `unwrap`, `.ok()`、`unimplemented`, `unreachable`
- [x] check if there exists `cannot decrypt` log
- [x] test with shadowsocks
- [x] remove unnecessary `clone` ~~(maybe this is the cause of high CPU problem)~~
- [ ] find the reason of high CPU (5% ~ 20%)
- [ ] handle the timeout situation of client 
- [ ] review `tcp_processor`
- [ ] refactor error handle
- [ ] handle DNS error properly (e.g. remove caller or call `resolve` again)
- [ ] finish all TODO items in source

#Test
* http://huaban.com/
* http://www.bilibili.com/
* http://www.panda.tv/
