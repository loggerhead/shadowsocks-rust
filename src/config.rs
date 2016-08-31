use std::fmt;
use std::rc::Rc;
use std::fs::File;
use std::error::Error;
use std::io::prelude::*;

use toml::{Parser, Value, Table};


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

pub fn get_config(config_path: &str) -> Result<Table, ConfigError> {
    let mut f = match File::open(config_path) {
        Ok(f) => f,
        Err(_) => {
            let errmsg = format!("config file {} does not exists", config_path);
            return Err(ConfigError::new(errmsg));
        }
    };

    let mut input = String::new();
    match f.read_to_string(&mut input) {
        Ok(_) => {},
        Err(_) => {
            let errmsg = format!("config file {} is not valid UTF-8 file", config_path);
            return Err(ConfigError::new(errmsg));
        }
    }

    let mut parser = Parser::new(&input);
    match parser.parse() {
        Some(mut config) => {
            set_default!(config, "local_address", "127.0.0.1", str);
            set_default!(config, "local_port", 8088, i64);
            set_default!(config, "timeout", 300, i64);
            set_default!(config, "method", "aes-256-cfb", str);

            Ok(config)
        }
        None => {
            let errmsg = format!("parse errors: {:?}", parser.errors);
            Err(ConfigError::new(errmsg))
        }
    }
}

pub fn get_str<'a>(conf: &'a Rc<Table>, key: &str) -> &'a str {
    conf.get(key).unwrap().as_str().unwrap()
}

pub fn get_i64(conf: &Rc<Table>, key: &str) -> i64 {
    conf.get(key).unwrap().as_integer().unwrap()
}
