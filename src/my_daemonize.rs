use std::str::FromStr;

#[derive(PartialEq, Eq)]
pub enum Cmd {
    Stop,
    Start,
    Restart,
    Unknown,
}

impl FromStr for Cmd {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "stop" => Ok(Cmd::Stop),
            "start" => Ok(Cmd::Start),
            "restart" => Ok(Cmd::Restart),
            _ => Err(format!("invalid daemon command: {}", s)),
        }
    }
}

pub use self::_daemonize::init;

#[cfg(target_family = "unix")]
mod _daemonize {
    extern crate sig;
    extern crate daemonize;

    use std::io::Read;
    use std::str::FromStr;
    use std::process::exit;
    use std::{thread, time};
    use std::fs::{File, remove_file};
    use std::path::PathBuf;

    use super::Cmd;

    pub fn init(daemon: Cmd, pid_file: &PathBuf) {
        match daemon {
            Cmd::Start => daemon_start(pid_file),
            Cmd::Stop => {
                daemon_stop(pid_file);
                exit(0);
            }
            Cmd::Restart => {
                daemon_stop(pid_file);
                daemon_start(pid_file);
            }
            _ => {}
        }
    }

    fn daemon_start(pid_file: &PathBuf) {
        let d = daemonize::Daemonize::new().pid_file(pid_file);
        if let Err(e) = d.start() {
            error!("daemonize failed: {}", e);
            exit(1);
        }
    }

    fn daemon_stop(pid_file: &PathBuf) {
        let mut f = match File::open(pid_file) {
            Ok(f) => f,
            Err(e) => {
                error!("cannot open pid file: {}", e);
                return;
            }
        };
        let mut pid = String::new();
        if let Err(e) = f.read_to_string(&mut pid) {
            error!("read pid file failed: {}", e);
            return;
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
mod _daemonize {
    use std::path::PathBuf;
    use super::Cmd;

    pub fn init(daemon: Cmd, pid_file: &PathBuf) {
    }
}
