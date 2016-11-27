use std::fmt;
use std::env;
use std::fs;
use std::sync::Arc;
use std::path::PathBuf;
use std::default::Default;

use my_daemonize;
use mode::Mode;
use crypto::Method;
use super::{ConfigError, ConfigResult, ProxyConfig};

macro_rules! create_set_fn {
    ($name:ident, $t:ty) => {
        pub fn $name(&mut self, val: Option<$t>) -> ConfigResult<()> {
            Arc::get_mut(&mut self.proxy_conf).unwrap().$name(val)?;
            Ok(())
        }
    }
}

pub struct RunningConfig {
    pub daemon: my_daemonize::Cmd,
    pub log_level: i8,
    pub log_file: Option<PathBuf>,
    pub pid_file: PathBuf,
    pub prefer_ipv6: bool,
    pub mode: Mode,
    pub proxy_conf: Arc<ProxyConfig>,
    pub server_confs: Option<Vec<Arc<ProxyConfig>>>,
}

impl fmt::Display for RunningConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut s = format!("{}\nprefer_ipv6 = {}", self.proxy_conf, self.prefer_ipv6);
        match self.mode {
            Mode::None => {}
            _ => s = format!("{}\nmode = \"{}\"", s, self.mode),
        }
        if let Some(ref p) = self.log_file {
            s = format!("{}\nlog_file = \"{}\"", s, p.display());
        }
        s = format!("{}\npid_file = \"{}\"", s, self.pid_file.display());

        if let Some(ref servers) = self.server_confs {
            for server in servers {
                s = format!("{}\n\n[[servers]]\n{}", s, server);
            }
        }

        write!(f, "{}", s)
    }
}

impl fmt::Debug for RunningConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = format!("log_level: {}\n\
                         log_file: {:?}\n\
                         pid_file: {:?}\n\
                         prefer_ipv6: {}\n\
                         mode: {:?}\n\
                         proxy_conf: {{\n\
                         {:?}\n\
                         }}\n\
                         server_confs: {:?}",
                        self.log_level,
                        self.log_file,
                        self.pid_file,
                        self.prefer_ipv6,
                        self.mode,
                        self.proxy_conf,
                        self.server_confs);

        write!(f, "{}", s)
    }
}

impl Default for RunningConfig {
    fn default() -> Self {
        let mode = if cfg!(feature = "sslocal") {
            Mode::Balance
        } else {
            Mode::None
        };

        RunningConfig {
            daemon: my_daemonize::Cmd::None,
            log_level: 0,
            log_file: None,
            pid_file: Self::default_pid_path(),
            prefer_ipv6: false,
            mode: mode,
            proxy_conf: Arc::new(ProxyConfig::default()),
            server_confs: None,
        }
    }
}

impl RunningConfig {
    // return "~/.shadowsocks/<file_name>" or "<file_name>"
    fn default_file_path(file_name: &str) -> PathBuf {
        env::home_dir()
            .and_then(|mut path| {
                path.push(".shadowsocks");
                try_opt!(fs::create_dir_all(&path).ok());
                path.push(file_name);
                Some(path)
            })
            .or(Some(PathBuf::from(file_name)))
            .unwrap()
    }

    pub fn default_config_path() -> PathBuf {
        let name = if cfg!(feature = "sslocal") {
            "sslocal.toml"
        } else {
            "ssserver.toml"
        };
        Self::default_file_path(name)
    }

    pub fn default_log_path() -> PathBuf {
        let log_file = if cfg!(feature = "sslocal") {
            "sslocal.log"
        } else {
            "ssserver.log"
        };
        Self::default_file_path(log_file)
    }

    pub fn default_pid_path() -> PathBuf {
        let pid_file = if cfg!(feature = "sslocal") {
            "sslocal.pid"
        } else {
            "ssserver.pid"
        };
        Self::default_file_path(pid_file)
    }

    pub fn address(&self) -> &String {
        &self.proxy_conf.address
    }

    pub fn port(&self) -> u16 {
        self.proxy_conf.port
    }

    pub fn method(&self) -> Method {
        self.proxy_conf.method
    }

    pub fn password(&self) -> &String {
        &self.proxy_conf.password
    }

    pub fn timeout(&self) -> u16 {
        self.proxy_conf.timeout
    }

    pub fn one_time_auth(&self) -> bool {
        self.proxy_conf.one_time_auth
    }

    pub fn set_quiet(&mut self, val: Option<i64>) -> ConfigResult<()> {
        if let Some(v) = val {
            if v < 0 {
                return Err(ConfigError::OutOfRange(v));
            } else {
                self.log_level = -v as i8;
            }
        }
        Ok(())
    }

    pub fn set_verbose(&mut self, val: Option<i64>) -> ConfigResult<()> {
        if let Some(v) = val {
            if v < 0 {
                return Err(ConfigError::OutOfRange(v));
            } else {
                self.log_level = v as i8;
            }
        }
        Ok(())
    }

    pub fn set_log_file(&mut self, val: Option<&str>) -> ConfigResult<()> {
        if val.is_some() {
            self.log_file = val.map(PathBuf::from);
        }
        Ok(())
    }

    pub fn set_pid_file(&mut self, val: Option<&str>) -> ConfigResult<()> {
        if let Some(p) = val {
            self.pid_file = PathBuf::from(p);
        }
        Ok(())
    }

    pub fn set_prefer_ipv6(&mut self, val: Option<bool>) -> ConfigResult<()> {
        if let Some(v) = val {
            self.prefer_ipv6 = v;
        }
        Ok(())
    }

    pub fn set_daemon(&mut self, val: Option<&str>) -> ConfigResult<()> {
        if let Some(v) = val {
            self.daemon = v.parse::<my_daemonize::Cmd>().map_err(ConfigError::Other)?;
        }
        Ok(())
    }

    pub fn set_mode(&mut self, val: Option<&str>) -> ConfigResult<()> {
        if let Some(v) = val {
            match v {
                "balance" => self.mode = Mode::Balance,
                "fast" => self.mode = Mode::Fast,
                _ => return Err(ConfigError::InvalidMode(v.to_string())),
            }
        }
        Ok(())
    }

    create_set_fn!(set_address, &str);
    create_set_fn!(set_port, i64);
    create_set_fn!(set_method, &str);
    create_set_fn!(set_password, &str);
    create_set_fn!(set_timeout, i64);
    create_set_fn!(set_one_time_auth, bool);
}
