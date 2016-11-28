use std::fmt;
use std::fs::{File, OpenOptions};
use std::sync::Arc;
use std::path::Path;
use std::io::prelude::*;

use toml::{Parser, Value, Table};

use super::{ConfigError, ConfigResult, Config, ProxyConfig};

macro_rules! tbl_get {
    ($t:expr, $name:expr, str) => { tbl_get!($t, $name, Value::as_str, "str") };
    ($t:expr, $name:expr, int) => { tbl_get!($t, $name, Value::as_integer, "int") };
    ($t:expr, $name:expr, bool) => { tbl_get!($t, $name, Value::as_bool, "bool") };
    ($t:expr, $name:expr, slice) => { tbl_get!($t, $name, Value::as_slice, "array") };
    ($t:expr, $name:expr, $f:expr, $ty:expr) => {
        match $t.get($name) {
            Some(raw_val) => {
                match $f(raw_val) {
                    None => Err(ConfigError::Other(format!("\"{} = {}\" is not {} type",
                                                           $name, raw_val, $ty))),
                    v => Ok(v)
                }
            }
            None => Ok(None)
        }
    };
}

pub fn check_and_set_from_toml(tbl: &Table, conf: &mut Config) -> ConfigResult<()> {
    conf.set_quiet(tbl_get!(tbl, "quiet", int)?)?;
    conf.set_verbose(tbl_get!(tbl, "verbose", int)?)?;
    conf.set_log_file(tbl_get!(tbl, "log_file", str)?)?;
    conf.set_pid_file(tbl_get!(tbl, "pid_file", str)?)?;
    conf.set_prefer_ipv6(tbl_get!(tbl, "prefer_ipv6", bool)?)?;
    conf.set_mode(tbl_get!(tbl, "mode", str)?)?;
    if let Some(true) = tbl_get!(tbl, "daemon", bool)? {
        conf.set_daemon(Some("start"))?;
    }

    conf.set_address(tbl_get!(tbl, "address", str)?)?;
    conf.set_port(tbl_get!(tbl, "port", int)?)?;
    conf.set_method(tbl_get!(tbl, "method", str)?)?;
    conf.set_password(tbl_get!(tbl, "password", str)?)?;
    conf.set_timeout(tbl_get!(tbl, "timeout", int)?)?;
    conf.set_one_time_auth(tbl_get!(tbl, "one_time_auth", bool)?)?;
    Ok(())
}

pub fn check_and_set_servers_from_toml(tbl: &Table, conf: &mut Config) -> ConfigResult<()> {
    let servers = tbl_get!(tbl, "servers", slice)?.ok_or(ConfigError::MissServerAddress)?;
    let mut server_confs = vec![];

    for server in servers {
        match *server {
            Value::Table(ref tbl) => {
                let mut server_conf = conf.proxy_conf.clone();

                {
                    let mut tmp = Arc::make_mut(&mut server_conf);

                    if let Some(address) = tbl.get("address") {
                        tmp.set_address(address.as_str())?;
                    } else {
                        return Err(ConfigError::MissServerAddress);
                    }
                    if let Some(port) = tbl.get("port") {
                        tmp.set_port(port.as_integer())?;
                    } else {
                        return Err(ConfigError::MissServerPort);
                    }

                    tmp.set_method(tbl_get!(tbl, "method", str)?)?;
                    tmp.set_password(tbl_get!(tbl, "password", str)?)?;
                    tmp.set_timeout(tbl_get!(tbl, "timeout", int)?)?;
                    tmp.set_one_time_auth(tbl_get!(tbl, "one_time_auth", bool)?)?;
                }

                server_confs.push(server_conf);
            }
            _ => {
                let errmsg = format!("server config should be table:\n{}", server);
                return Err(ConfigError::ParseConfigFailed(errmsg));
            }
        }
    }

    conf.server_confs = Some(server_confs);
    Ok(())
}

pub fn read_config<P: AsRef<Path> + fmt::Debug>(config_path: P) -> Result<Table, ConfigError> {
    let mut f = File::open(&config_path).map_err(|e| {
            let errmsg = format!("{} ({})", config_path.as_ref().display(), e);
            ConfigError::OpenFileFailed(errmsg)
        })?;

    let mut input = String::new();
    f.read_to_string(&mut input)
        .map_err(|e| {
            let errmsg = format!("{} is not valid UTF-8 file ({})",
                                 config_path.as_ref().display(),
                                 e);
            ConfigError::OpenFileFailed(errmsg)
        })?;

    let mut parser = Parser::new(&input);
    match parser.parse() {
        Some(config) => Ok(config),
        None => {
            let mut errmsg = String::new();
            for e in &parser.errors {
                errmsg = format!("{}\n{}", errmsg, e);
            }
            Err(ConfigError::ParseConfigFailed(errmsg))
        }
    }
}

pub fn save_if_not_exists(conf: &Config) {
    let path = Config::default_config_path();
    if path.exists() {
        return;
    }

    if let Ok(ref mut f) = File::create(&path) {
        let content = format!("{}\n", conf);
        let _ = f.write_all(content.as_bytes());
    }
}

pub fn append_to_default_config(server_conf: &ProxyConfig) {
    let path = Config::default_config_path();
    let _ = OpenOptions::new().append(true).open(path).and_then(|mut f| {
        let content = format!("\n[[servers]]\n{}\n", server_conf);
        f.write_all(content.as_bytes())
    });
}
