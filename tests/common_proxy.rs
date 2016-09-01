extern crate shadowsocks;

use std::thread;
use std::process::{Command, Output};

use shadowsocks::config;
use shadowsocks::relay::Relay;

#[test]
fn main() {
    let tests = vec![
        "www.baidu.com",
        "www.qq.com"
    ];

    // TODO: change to get args from command line
    let threads = vec![
        start_client("tests/config/local_conf.toml"),
        start_server("tests/config/server_conf.toml"),
    ];

    for test in tests {
        let res1 = run_curl(test, None);
        let res2 = run_curl(test, Some("127.0.0.1:8388"));
        assert_eq!(res1, res2);
    }

    for t in threads {
        t.join().unwrap();
    }
}

fn start_ss(config_path: &str, is_client: bool) -> thread::JoinHandle<()> {
    let conf = config::get_config(config_path);
    assert!(conf.is_ok());

    thread::spawn(move || {
        Relay::new(conf.unwrap(), is_client).run();
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
    cmd.arg(url).arg("-v").arg("-L")
       .arg("-m").arg("15")
       .arg("--connect-timeout").arg("10");

    if proxy.is_some() {
        cmd.arg("--socks5-hostname").arg(proxy.unwrap());
    }

    cmd.spawn().expect("failed to execute cmd")
       .wait_with_output().expect("failed to wait on child")
}
