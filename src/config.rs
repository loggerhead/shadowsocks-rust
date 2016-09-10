use std::fmt;
use std::rc::Rc;
use std::fs::File;
use std::ops::Index;
use std::error::Error;
use std::clone::Clone;
use std::io::prelude::*;

use toml::{Parser, Value, Table};

pub struct Config {
    values: Rc<Table>,
}

impl Config {
    fn new(conf: Table) -> Self {
        Config {
            values: Rc::new(conf),
        }
    }

    fn get(&self, key: &'static str) -> Option<&Value> {
        self.values.get(key)
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
        Config {
            values: self.values.clone(),
        }
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
        ConfigError {
            desc: desc
        }
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


macro_rules! check_config {
    ($conf:expr, $key:expr) => (
        if !$conf.contains_key($key) {
            let errmsg = format!("parse errors: no {}", $key);
            return Err(ConfigError::new(errmsg));
        }
    );
}

macro_rules! set_default {
    ($conf:expr, $key:expr, $value:expr, str) => (
        let v = Value::String($value.to_string());
        $conf.entry($key.to_string()).or_insert(v);
    );
    ($conf:expr, $key:expr, $value:expr, i64) => (
        let v = Value::Integer($value);
        $conf.entry($key.to_string()).or_insert(v);
    );
}

pub fn read_config(config_path: &str) -> Result<Config, ConfigError> {
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
        Some(mut config) => {
            if cfg!(feature = "is_client") {
                check_config!(config, "servers");
                set_default!(config, "listen_address", "127.0.0.1", str);
            } else {
                set_default!(config, "listen_address", "0.0.0.0", str);
            }

            check_config!(config, "password");

            set_default!(config, "listen_port", 8010, i64);
            set_default!(config, "timeout", 300, i64);
            set_default!(config, "encrypt_method", "aes-256-cfb", str);
            Ok(Config::new(config))
        }
        None => {
            let errmsg = format!("parse errors: {:?}", parser.errors);
            Err(ConfigError::new(errmsg))
        }
    }
}