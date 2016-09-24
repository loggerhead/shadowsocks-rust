use std::fmt;
use std::rc::Rc;
use std::fs::File;
use std::ops::Index;
use std::str::FromStr;
use std::error::Error;
use std::clone::Clone;
use std::io::prelude::*;

use clap::{Arg, App, ArgMatches};
use toml::{Parser, Value, Table, Array};

pub struct Config {
    values: Rc<Table>,
}

impl Config {
    fn new(conf: Table) -> Self {
        Config { values: Rc::new(conf) }
    }

    pub fn get(&self, key: &'static str) -> Option<&Value> {
        self.values.get(key)
    }

    pub fn get_i64(&self, key: &'static str) -> Option<i64> {
        self.values.get(key).map(|v| v.as_integer().unwrap())
    }

    pub fn get_bool(&self, key: &'static str) -> Option<bool> {
        self.values.get(key).map(|v| v.as_bool().unwrap())
    }
}

impl Index<&'static str> for Config {
    type Output = Value;

    fn index<'a>(&'a self, index: &'static str) -> &'a Self::Output {
        self.get(index).unwrap()
    }
}

impl Clone for Config {
    fn clone(&self) -> Self {
        Config { values: self.values.clone() }
    }

    fn clone_from(&mut self, source: &Self) {
        self.values = source.values.clone();
    }
}

#[derive(Debug)]
pub struct ConfigError {
    desc: String,
}

impl ConfigError {
    fn new(desc: String) -> ConfigError {
        ConfigError { desc: desc }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.desc)
    }
}

impl Error for ConfigError {
    fn description(&self) -> &str {
        &self.desc
    }
}

pub fn gen_config() -> Result<Config, ConfigError> {
    let mut args = App::new("A fast tunnel proxy that helps you bypass firewalls.")
        .about("You can supply configurations via either config file or command line arguments.")
        .arg(Arg::with_name("config")
            .short("c")
            .value_name("path")
            .help("path to config file")
            .takes_value(true))
        .arg(Arg::with_name("password")
            .short("k")
            .value_name("password")
            .help("password")
            .takes_value(true))
        .arg(Arg::with_name("encryption_method")
            .short("m")
            .value_name("method")
            .help("encryption method")
            .default_value("aes-256-ctr"))
        .arg(Arg::with_name("timeout")
            .short("t")
            .value_name("timeout")
            .help("timeout in seconds")
            .default_value("300"))
        .arg(Arg::with_name("fast_open")
            .long("fast-open")
            .help("use TCP_FASTOPEN, requires Linux 3.7+"))
        .arg(Arg::with_name("verbose")
            .short("v")
            .multiple(true)
            .help("sets the level of verbosity"))
        .arg(Arg::with_name("quiet")
            .short("q")
            .multiple(true)
            .help("quiet mode, only show warnings/errors"))
        .arg(Arg::with_name("daemon")
            .short("d")
            .help("daemon mode")
            .takes_value(true)
            .possible_values(&["start", "stop", "restart"]))
        .arg(Arg::with_name("pid_file")
            .long("pid-file")
            .value_name("pid_file")
            .help("pid file for daemon mode")
            .takes_value(true))
        .arg(Arg::with_name("log_file")
            .long("log-file")
            .value_name("log_file")
            .help("log file for daemon mode")
            .takes_value(true));
    if cfg!(feature = "is_client") {
        args = args.arg(Arg::with_name("server")
            .short("s")
            .value_name("ip:port")
            .help("server address and port")
            .takes_value(true));
    }

    let (addr, port) = if cfg!(feature = "is_client") {
        ("127.0.0.1", "8010")
    } else {
        ("0.0.0.0", "8111")
    };
    args = args.arg(Arg::with_name("listen_address")
            .short("b")
            .value_name("address")
            .help("binding address")
            .default_value(addr))
        .arg(Arg::with_name("listen_port")
            .short("p")
            .value_name("port")
            .help("local port")
            .default_value(port));

    let matches = args.get_matches();
    let config = match matches.value_of("config") {
        Some(config_path) => {
            match read_config(config_path) {
                Ok(config) => config,
                Err(e) => return Err(e),
            }
        }
        _ => Table::new(),
    };

    check_config(matches, config)
}

pub fn read_config(config_path: &str) -> Result<Table, ConfigError> {
    let mut f = match File::open(config_path) {
        Ok(f) => f,
        Err(_) => {
            let errmsg = format!("config file {} does not exists", config_path);
            return Err(ConfigError::new(errmsg));
        }
    };

    let mut input = String::new();
    if let Err(_) = f.read_to_string(&mut input) {
        let errmsg = format!("config file {} is not valid UTF-8 file", config_path);
        return Err(ConfigError::new(errmsg));
    }

    let mut parser = Parser::new(&input);
    match parser.parse() {
        Some(config) => Ok(config),
        None => {
            let errmsg = format!("parse errors: {:?}", parser.errors);
            Err(ConfigError::new(errmsg))
        }
    }
}

pub fn check_config(matches: ArgMatches, mut config: Table) -> Result<Config, ConfigError> {
    macro_rules! check_config {
        ($key:expr) => (
            if !matches.is_present($key) && !config.contains_key($key) {
                let errmsg = format!("'{}' value is missing", $key);
                return Err(ConfigError::new(errmsg));
            }
        )
    }

    macro_rules! try_set_config {
        ($key:expr, check) => (
            check_config!($key);
            try_set_config!($key)
        );
        ($key:expr, i64, check) => (
            check_config!($key);
            try_set_config!($key, i64)
        );
        ($key:expr) => (
            {
                fn parse(v: &str) -> Result<Value, ConfigError> {
                    Ok(Value::String(v.to_string()))
                }
                try_set_config!($key, parse);
            }
        );
        ($key:expr, i64) => (
            {
                fn parse(v: &str) -> Result<Value, ConfigError> {
                    match i64::from_str(v) {
                        Ok(v) => Ok(Value::Integer(v)),
                        _ => {
                            let errmsg = format!("'{}' is not a valid number", $key);
                            Err(ConfigError::new(errmsg))
                        }
                    }
                }
                try_set_config!($key, parse);
            }
        );
        ($key:expr, bool) => (
            let k = $key.to_string();
            let v = matches.is_present(&k);
            config.entry(k).or_insert(Value::Boolean(v));
        );
        ($key:expr, $parse_val:ident) => (
            let k = $key.to_string();
            if let Some(v) = matches.value_of(&k) {
                match $parse_val(v) {
                    Ok(v) => {
                        config.insert(k, v);
                    }
                    Err(e) => return Err(e),
                }
            }
        )
    }

    if cfg!(feature = "is_client") {
        if let Some(server) = matches.value_of("server") {
            let mut servers = Array::new();
            servers.push(Value::String(server.to_string()));
            config.insert("servers".to_string(), Value::Array(servers));
        } else if !config.contains_key("servers") {
            return Err(ConfigError::new("ssserver address is missing".to_string()));
        }
    }

    try_set_config!("listen_address", check);
    try_set_config!("listen_port", i64, check);
    try_set_config!("password", check);
    try_set_config!("timeout", i64, check);
    try_set_config!("encryption_method", check);

    try_set_config!("fast_open", bool);
    try_set_config!("verbose", i64);
    try_set_config!("quiet", i64);
    try_set_config!("daemon");
    try_set_config!("pid_file");
    try_set_config!("log_file");

    Ok(Config::new(config))
}