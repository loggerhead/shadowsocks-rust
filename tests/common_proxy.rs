extern crate shadowsocks;

use std::thread;
use std::process::{Command, Output};

use shadowsocks::config;
use shadowsocks::relay::Relay;


const URLS: &'static [&'static str] =
    &["https://www.baidu.com/", "https://news.ycombinator.com/news/", "http://test-ipv6.com/"];


#[test]
fn main() {
    // TODO: change to get args from command line
    // TODO: to use curl lib, see tokio-socks/tests
    start_client("tests/config/local_conf.toml");
    start_server("tests/config/server_conf.toml");

    for _ in 0..10000 {

    }

    let threads = URLS.iter().map(|url| {
        thread::spawn(move || {
            let res1 = run_curl(url, None);
            let res2 = run_curl(url, Some("127.0.0.1:8488"));
            assert_eq!(res1.status, res2.status, "{}", url);
            assert!(res1.stdout == res2.stdout,
                    "output of curl not equal: {}",
                    url);

            // if res1.stdout != res2.stdout {
            //     use std::str;
            //     use std::fs::File;
            //     use std::io::prelude::*;
            //
            //     let res1 = unsafe {str::from_utf8_unchecked(&res1.stdout)};
            //     let res2 = unsafe {str::from_utf8_unchecked(&res2.stdout)};
            //
            //     let mut f1 = File::create("res1.txt").unwrap();
            //     let mut f2 = File::create("res2.txt").unwrap();
            //     f1.write_all(res1.as_bytes()).unwrap();
            //     f2.write_all(res2.as_bytes()).unwrap();
            //     assert!(false, "{}", url);
            // }
        })
    });

    for t in threads {
        t.join().unwrap();
    }
}

fn start_ss(config_path: &str) -> thread::JoinHandle<()> {
    let conf = config::get_config(config_path);
    assert!(conf.is_ok());

    thread::spawn(move || {
        Relay::new(conf.unwrap()).run();
    })
}

fn start_client(config_path: &str) -> thread::JoinHandle<()> {
    start_ss(config_path, true)
}

fn start_server(config_path: &str) -> thread::JoinHandle<()> {
    start_ss(config_path, false)
}

fn run_curl(url: &str, proxy: Option<&str>) -> Output {
    let mut cmd = Command::new("curl");
    cmd.arg(url)
        .arg("-v")
        .arg("-L")
        .arg("-m")
        .arg("15")
        .arg("--connect-timeout")
        .arg("10");

    if let Some(proxy_address) = proxy {
        cmd.arg("--socks5-hostname").arg(proxy_address);
    }

    cmd.output().expect("failed to execute cmd")
}