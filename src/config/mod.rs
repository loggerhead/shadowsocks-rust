use std::fmt;
use std::sync::Arc;
use std::net::{TcpStream, ToSocketAddrs};
use std::io::prelude::*;
use std::process::exit;
use std::path::PathBuf;

use toml::Value;

use my_logger;
use my_daemonize;

#[macro_use]
mod toml;
mod cmd;
mod proxy_config;
mod running_config;

use self::cmd::{parse_cmds, check_and_set_from_args, check_and_set_server_from_args};
use self::toml::{read_config, save_if_not_exists, append_to_default_config,
                 check_and_set_from_toml, check_and_set_servers_from_toml};

pub use self::proxy_config::ProxyConfig;
pub use self::running_config::RunningConfig as Config;

pub type ConfigResult<T> = Result<T, ConfigError>;

pub enum ConfigError {
    MissServerMethod,
    MissServerPassword,
    MissServerAddress,
    MissServerPort,
    OpenFileFailed(String),
    ParseConfigFailed(String),
    InvalidMode(String),
    InvalidMethod(String),
    InvalidNumber(String),
    InvalidAddress(String),
    OutOfRange(i64),
    Other(String),
}

impl fmt::Debug for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ConfigError::MissServerMethod => write!(f, "server method is missing"),
            ConfigError::MissServerPassword => write!(f, "server password is missing"),
            ConfigError::MissServerAddress => write!(f, "server address is missing"),
            ConfigError::MissServerPort => write!(f, "server port is missing"),
            ConfigError::OpenFileFailed(ref desc) => write!(f, "open config file failed: {}", desc),
            ConfigError::ParseConfigFailed(ref desc) => {
                write!(f, "parse config file error: {}", desc)
            }
            ConfigError::InvalidMode(ref desc) => write!(f, "invalid mode: {}", desc),
            ConfigError::InvalidMethod(ref desc) => {
                write!(f, "invalid encryption method: {}", desc)
            }
            ConfigError::InvalidNumber(ref desc) => write!(f, "invalid number: {}", desc),
            ConfigError::InvalidAddress(ref desc) => write!(f, "invalid address: {}", desc),
            ConfigError::OutOfRange(n) => write!(f, "{} is out of range", n),
            ConfigError::Other(ref desc) => write!(f, "{}", desc),
        }
    }
}

/// The working config follows a few rules:
/// 1. Command line is prior to config file.
/// 2. If no arguments provide, then read from default config file.
/// 3. If default config file doesn't exists, then randomly generated one and save it.
pub fn init_config() -> Result<Arc<Config>, ConfigError> {
    let config_path = Config::default_config_path();
    let args = parse_cmds();
    let toml: Result<_, _> =
        args.value_of("config").or(config_path.to_str()).map(read_config).unwrap();
    let use_default_config = args.args.is_empty() ||
                             (args.args.contains_key("daemon") && args.args.len() == 1);

    // daemon
    let daemon = if let Some(cmd) = args.value_of("daemon") {
        cmd.parse::<my_daemonize::Cmd>().map_err(ConfigError::Other)?
    } else if let Ok(Some(true)) = toml.as_ref()
        .map(|t| tbl_get!(t, "daemon", bool)) {
        my_daemonize::Cmd::Start
    } else if use_default_config {
        my_daemonize::Cmd::Start
    } else {
        my_daemonize::Cmd::None
    };

    // pid-file
    let pid_file = if let Some(path) = args.value_of("pid_file") {
        PathBuf::from(path)
    } else if let Ok(Some(path)) = toml.as_ref()
        .map(|t| tbl_get!(t, "pid_file", str)) {
        PathBuf::from(path)
    } else {
        Config::default_pid_path()
    };

    if daemon == my_daemonize::Cmd::Stop {
        my_daemonize::init(my_daemonize::Cmd::Stop, &pid_file);
    }

    let mut conf = Config::default();
    conf.pid_file = Some(pid_file);

    if cfg!(feature = "sslocal") {
        if let Some(server_conf) = args.value_of("add_server") {
            let mut tmp = Arc::make_mut(&mut conf.proxy_conf);
            tmp.base64_decode(server_conf)?;
            append_to_default_config(tmp);
            exit(0);
        }
    }

    // if no arguments available from command line
    if use_default_config {
        if cfg!(feature = "sslocal") {
            let tbl = toml?;
            check_and_set_from_toml(&tbl, &mut conf)?;
            check_and_set_servers_from_toml(&tbl, &mut conf)?;
            println!("start sslocal with default config");
        } else {
            if config_path.exists() {
                let tbl = toml?;
                check_and_set_from_toml(&tbl, &mut conf)?;
                println!("start ssserver with default config");
            } else {
                {
                    // set `address` to external ip
                    let mut tmp = Arc::make_mut(&mut conf.proxy_conf);
                    let ip = get_external_ip().ok_or(
                        ConfigError::Other("cannot get external ip".to_string()))?;
                    tmp.set_address(Some(ip.as_str()))?;
                }
                println!("{}", conf.proxy_conf.base64_encode());
                save_if_not_exists(&conf);
            }
        }
    } else {
        if args.value_of("config").is_some() {
            match toml {
                Ok(tbl) => {
                    check_and_set_from_toml(&tbl, &mut conf)?;
                    check_and_set_from_args(&args, &mut conf)?;
                    // setup `server` or `servers`
                    if cfg!(feature = "sslocal") {
                        check_and_set_servers_from_toml(&tbl, &mut conf)?;
                    }
                }
                Err(e) => return Err(e),
            }
        }

        if cfg!(feature = "sslocal") && args.value_of("server").is_some() {
            check_and_set_server_from_args(&args, &mut conf)?;
        }

        // 1. setup config from input
        // 2. save it if default config file is not exists
        if let Some(input) = args.value_of("input") {
            let mut proxy_conf = ProxyConfig::default();
            proxy_conf.base64_decode(input)?;
            let proxy_conf = Arc::new(proxy_conf);
            if cfg!(feature = "sslocal") {
                conf.server_confs = Some(vec![proxy_conf]);
            } else {
                conf.proxy_conf = proxy_conf;
            }
            save_if_not_exists(&conf);
        }

        if cfg!(feature = "sslocal") && conf.server_confs.is_none() {
            return Err(ConfigError::MissServerAddress);
        }
    }

    match daemon {
        my_daemonize::Cmd::Start |
        my_daemonize::Cmd::Restart => {
            my_daemonize::init(daemon, conf.pid_file.as_ref().unwrap());
            if conf.log_file.is_none() {
                conf.log_file = Some(Config::default_log_path());
            }
        }
        _ => {}
    }

    my_logger::init(conf.log_level, conf.log_file.as_ref()).map_err(|e| {
            let errmsg = format!("init logger failed: {}", e);
            ConfigError::Other(errmsg)
        })?;

    Ok(Arc::new(conf))
}

const HOST_PATHS: &'static [(&'static str, &'static str)] = &[("ident.me", "/"),
                                                              ("icanhazip.com", "/")];

fn get_external_ip() -> Option<String> {
    for host_path in HOST_PATHS {
        let ip = echo_ip(host_path.0, host_path.1);
        if ip.is_some() {
            return ip;
        }
    }
    None
}

fn echo_ip(host: &str, path: &str) -> Option<String> {
    let addr = try_opt!((host, 80).to_socket_addrs().ok().and_then(|mut addrs| addrs.next()));
    let mut conn = try_opt!(TcpStream::connect(addr).ok());
    let r = format!("GET {} HTTP/1.1\r\nHost: {}\r\n\r\n", path, host);
    try_opt!(conn.write_all(r.as_bytes()).ok());
    let mut s = String::new();
    try_opt!(conn.read_to_string(&mut s).ok());

    // handle HTTP chunks
    let mut lines: Vec<&str> = s.trim().lines().collect();
    let mut ip = lines.pop();
    if ip == Some("0") {
        ip = lines.pop().map(|l| l.trim());
    }
    ip.map(|s| s.to_string())
}
