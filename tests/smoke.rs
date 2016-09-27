// TODO: currently this test case is useless, check TODO item in `Cargo.toml`
// This test case is stolen from https://github.com/tokio-rs/tokio-socks5
// with little modified. So it will reserve Alex Crichton's attribution
// with great thankful.

// Copyright (c) 2016 Alex Crichton

// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:

// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
extern crate curl;

use std::env;
use std::io::{Read, Write};
use std::net::{TcpStream, TcpListener};
use std::path::PathBuf;
use std::process::{Command, Child};
use std::thread;
use std::time::Duration;

use curl::easy::Easy;

fn bin(name: &'static str) -> PathBuf {
    env::current_exe().unwrap().parent().unwrap().join(name)
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        self.0.kill().unwrap();
        self.0.wait().unwrap();
    }
}

#[test]
fn smoke() {
    let proxy_client_addr = "127.0.0.1:8010";
    let proxy_server_addr = "127.0.0.1:8111";
    // Spawn our proxy and wait for it to come online
    let proxy = Command::new(bin("sslocal"))
        .arg("-c")
        .arg("tests/config/client_conf.toml")
        .spawn()
        .unwrap();
    let _proxy = KillOnDrop(proxy);
    let proxy = Command::new(bin("ssserver"))
        .arg("-c")
        .arg("tests/config/server_conf.toml")
        .spawn()
        .unwrap();
    let _proxy = KillOnDrop(proxy);

    // wait
    loop {
        match TcpStream::connect(proxy_client_addr) {
            Ok(_) => break,
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
    loop {
        match TcpStream::connect(proxy_server_addr) {
            Ok(_) => break,
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0; 1024];
        while let Ok((mut conn, _)) = listener.accept() {
            let n = conn.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.starts_with("GET / HTTP/1.1\r\n"));

            conn.write_all(b"\
                HTTP/1.1 200 OK\r\n\
                Content-Length: 13\r\n\
                \r\n\
                Hello, World!\
            ")
                .unwrap();
        }
    });

    // Test socks5
    let mut handle = Easy::new();
    handle.get(true).unwrap();
    handle.url(&format!("http://{}/", server_addr)).unwrap();
    handle.proxy(&format!("socks5://{}", proxy_client_addr)).unwrap();
    let mut resp = Vec::new();
    {
        let mut transfer = handle.transfer();
        transfer.write_function(|data| {
                resp.extend_from_slice(data);
                Ok(data.len())
            })
            .unwrap();
        transfer.perform().unwrap();
    }
    assert_eq!(handle.response_code().unwrap(), 200);
    assert_eq!(resp.as_slice(), b"Hello, World!");
}
