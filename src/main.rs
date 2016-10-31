#[cfg(target_family = "unix")]
#[macro_use]
extern crate sig;
#[macro_use]
extern crate log;
extern crate shadowsocks;

use std::thread::spawn;
use std::process::exit;

use shadowsocks::config;
use shadowsocks::my_logger;
use shadowsocks::relay::{TcpRelay, UdpRelay};

fn main() {
    let conf = config::gen_config().unwrap_or_else(|e| {
        println!("config error: {}", e);
        exit(1);
    });
    my_logger::init(&conf).unwrap_or_else(|e| {
        println!("init logger failed: {}", e);
        exit(1);
    });

    my_daemonize::do_daemonize(&conf);

    let childs = vec![
        {
           let conf = conf.clone();
            spawn(|| {
                TcpRelay::new(conf).and_then(|r| r.run())
                    .unwrap_or_else(|e| error!("{}", e))
            })
        },
        {
            let conf = conf.clone();
            spawn(|| {
                UdpRelay::new(conf).and_then(|r| r.run())
                    .unwrap_or_else(|e| error!("{}", e))
            })
        },
    ];

    for child in childs {
        let _ = child.join();
    }
}

#[cfg(target_family = "unix")]
mod my_daemonize {
    extern crate sig;
    extern crate daemonize;

    use std::io::Read;
    use std::str::FromStr;
    use std::process::exit;
    use std::{thread, time};
    use std::fs::{File, remove_file};

    use shadowsocks::config::Config;

    pub fn do_daemonize(conf: &Config) {
        if conf.get("daemon").is_some() {
            let daemon = conf["daemon"].as_str().unwrap();
            let pid_file = conf["pid_file"].as_str().unwrap();

            if daemon == "start" {
                daemon_start(pid_file);
            } else if daemon == "stop" {
                daemon_stop(pid_file);
                exit(0);
            } else if daemon == "restart" {
                daemon_stop(pid_file);
                daemon_start(pid_file);
            }
        }
    }

    fn daemon_start(pid_file: &str) {
        let d = daemonize::Daemonize::new().pid_file(pid_file);
        if let Err(e) = d.start() {
            error!("daemonize failed: {}", e);
            return exit(1);
        }
    }

    fn daemon_stop(pid_file: &str) {
        let mut f = match File::open(pid_file) {
            Ok(f) => f,
            Err(e) => {
                error!("cannot open pid file: {}", e);
                return;
            }
        };
        let mut pid = String::new();
        match f.read_to_string(&mut pid) {
            Err(e) => {
                error!("read pid file failed: {}", e);
                return;
            }
            _ => {}
        }

        let pid = match i32::from_str(&pid) {
            Ok(pid) if pid > 0 => pid,
            _ => {
                error!("stop failed: `{}' is not a valid number", pid);
                return;
            }
        };

        if kill!(pid, sig::ffi::Sig::TERM) {
            if cfg!(feature = "sslocal") {
                error!("ssclient is not running: {}", pid);
            } else {
                error!("ssserver is not running: {}", pid);
            }
        }

        // sleep for maximum 10s
        let mut timeout = true;
        let nap = time::Duration::from_millis(50);
        for _ in 0..200 {
            if !kill!(pid, 0) {
                timeout = false;
                break;
            }
            thread::sleep(nap);
        }

        if timeout {
            error!("timed out when stopping pid {}", pid);
        } else {
            let _ = remove_file(pid_file);
        }
    }
}


#[cfg(not(target_family = "unix"))]
mod my_daemonize {
    use shadowsocks::config::Config;

    pub fn do_daemonize(_conf: &Config) {
        error!("not support daemonize feature");
    }
}
