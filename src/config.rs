use std::fmt;
use std::env;
use std::fs;
use std::sync::Arc;
use std::default::Default;
use std::path::PathBuf;
use std::fs::File;
use std::clone::Clone;
use std::io::prelude::*;

use rand::{Rng, thread_rng};
use clap::{Arg, App, ArgMatches};
use toml::{Parser, Value, Table};

use mode::Mode;
use crypto::Method;
use network::{is_ip, is_hostname};
use my_logger;
use my_daemonize;

type ConfigResult<T> = Result<T, ConfigError>;

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct ProxyConfig {
    pub address: String,
    pub port: u16,
    pub method: Method,
    pub password: String,
    pub timeout: u16,
    pub one_time_auth: bool,
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "address = {}\n\
                port = {}\n\
                method = {:?}\n\
                password = {}\n\
                timeout = {}\n\
                one_time_auth = {}",
               self.address,
               self.port,
               self.method,
               self.password,
               self.timeout,
               self.one_time_auth)
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        let mut rng = thread_rng();
        let address = String::from(if cfg!(feature = "sslocal") {
            "127.0.0.1"
        } else {
            "0.0.0.0"
        });

        let port = if cfg!(feature = "sslocal") {
            1080
        } else {
            rng.gen::<u16>()
        };

        let method = rng.choose(&Method::all()).cloned().or(Some(Method::aes_256_ctr)).unwrap();
        let password = rng.gen_ascii_chars().take(4).collect();
        let timeout = 60;
        let one_time_auth = false;

        ProxyConfig {
            address: address,
            port: port,
            method: method,
            password: password,
            timeout: timeout,
            one_time_auth: one_time_auth,
        }
    }
}

impl ProxyConfig {
    fn set_address(&mut self, val: Option<&str>) -> ConfigResult<bool> {
        match val {
            Some(v) => {
                if !(is_ip(v) || is_hostname(v)) {
                    Err(ConfigError::InvalidAddress(v.to_string()))
                } else {
                    self.address = v.to_string();
                    Ok(true)
                }
            }
            None => Ok(false),
        }
    }

    fn set_port(&mut self, val: Option<i64>) -> ConfigResult<bool> {
        match val {
            Some(v) => {
                if v < 0 || (u16::max_value() as i64) < v {
                    Err(ConfigError::OutOfRange(v))
                } else {
                    self.port = v as u16;
                    Ok(true)
                }
            }
            None => Ok(false),
        }
    }

    fn set_method(&mut self, val: Option<&str>) -> ConfigResult<bool> {
        match val {
            Some(v) => {
                Method::from(v)
                    .map(|m| {
                        self.method = m;
                        true
                    })
                    .ok_or(ConfigError::InvalidMethod(v.to_string()))
            }
            None => Ok(false),
        }
    }

    fn set_password(&mut self, val: Option<&str>) -> ConfigResult<bool> {
        match val {
            Some(v) => {
                self.password = v.to_string();
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn set_timeout(&mut self, val: Option<i64>) -> ConfigResult<bool> {
        match val {
            Some(v) => {
                if v < 0 {
                    Err(ConfigError::OutOfRange(v))
                } else {
                    self.timeout = v as u16;
                    Ok(true)
                }
            }
            None => Ok(false),
        }
    }

    fn set_one_time_auth(&mut self, val: Option<bool>) -> ConfigResult<bool> {
        match val {
            Some(v) => {
                self.one_time_auth = v;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

pub struct Config {
    pub log_level: i8,
    pub log_file: Option<PathBuf>,
    pub pid_file: Option<PathBuf>,
    pub prefer_ipv6: bool,
    pub mode: Mode,
    pub proxy_conf: Arc<ProxyConfig>,
    pub server_confs: Option<Vec<Arc<ProxyConfig>>>,
    pub is_modified: bool,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = format!("log_level: {}\n\
                         log_file: {:?}\n\
                         pid_file: {:?}\n\
                         prefer_ipv6: {}\n\
                         mode: {:?}\n\
                         proxy_conf: {{\n\
                         {:?}\n\
                         }}\n\
                         server_confs: {:?}\n\
                         is_modified: {}",
                        self.log_level,
                        self.log_file,
                        self.pid_file,
                        self.prefer_ipv6,
                        self.mode,
                        self.proxy_conf,
                        self.server_confs,
                        self.is_modified);

        write!(f, "{}", s)
    }
}

impl Default for Config {
    fn default() -> Self {
        let mode = if cfg!(feature = "sslocal") {
            Mode::Balance
        } else {
            Mode::None
        };

        Config {
            log_level: 0,
            log_file: None,
            pid_file: None,
            prefer_ipv6: false,
            mode: mode,
            proxy_conf: Arc::new(ProxyConfig::default()),
            server_confs: None,
            is_modified: false,
        }
    }
}

impl Config {
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

    // return "~/.shadowsocks/<file_name>" or "<file_name>"
    fn default_file_path(&self, file_name: &str) -> PathBuf {
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

    pub fn default_log_file(&self) -> PathBuf {
        let log_file = if cfg!(feature = "sslocal") {
            "sslocal.log"
        } else {
            "ssserver.log"
        };
        self.default_file_path(log_file)
    }

    pub fn default_pid_file(&self) -> PathBuf {
        let pid_file = if cfg!(feature = "sslocal") {
            "sslocal.pid"
        } else {
            "ssserver.pid"
        };
        self.default_file_path(pid_file)
    }

    fn set_quiet(mut self, val: Option<i64>) -> ConfigResult<Config> {
        if let Some(v) = val {
            if v < 0 {
                return Err(ConfigError::OutOfRange(v));
            } else {
                self.log_level = -v as i8;
            }
        }
        Ok(self)
    }

    fn set_verbose(mut self, val: Option<i64>) -> ConfigResult<Config> {
        if let Some(v) = val {
            if v < 0 {
                return Err(ConfigError::OutOfRange(v));
            } else {
                self.log_level = v as i8;
            }
        }
        Ok(self)
    }

    fn set_log_file(mut self, val: Option<&str>) -> ConfigResult<Config> {
        self.log_file = val.map(PathBuf::from);
        Ok(self)
    }

    fn set_pid_file(mut self, val: Option<&str>) -> ConfigResult<Config> {
        self.pid_file = val.map(PathBuf::from);
        Ok(self)
    }

    fn set_prefer_ipv6(mut self, val: Option<bool>) -> ConfigResult<Config> {
        if let Some(v) = val {
            self.prefer_ipv6 = v;
        }
        Ok(self)
    }

    fn set_mode(mut self, val: Option<&str>) -> ConfigResult<Config> {
        if let Some(v) = val {
            match v {
                "balance" => self.mode = Mode::Balance,
                "fast" => self.mode = Mode::Fast,
                _ => return Err(ConfigError::InvalidMode(v.to_string())),
            }
        }
        Ok(self)
    }

    fn set_address(mut self, val: Option<&str>) -> ConfigResult<Config> {
        Arc::get_mut(&mut self.proxy_conf).unwrap().set_address(val).map(|is_modified| {
            self.is_modified = is_modified;
            self
        })
    }

    fn set_port(mut self, val: Option<i64>) -> ConfigResult<Config> {
        Arc::get_mut(&mut self.proxy_conf).unwrap().set_port(val).map(|is_modified| {
            self.is_modified = is_modified;
            self
        })
    }

    fn set_method(mut self, val: Option<&str>) -> ConfigResult<Config> {
        Arc::get_mut(&mut self.proxy_conf).unwrap().set_method(val).map(|is_modified| {
            self.is_modified = is_modified;
            self
        })
    }

    fn set_password(mut self, val: Option<&str>) -> ConfigResult<Config> {
        Arc::get_mut(&mut self.proxy_conf).unwrap().set_password(val).map(|is_modified| {
            self.is_modified = is_modified;
            self
        })
    }

    fn set_timeout(mut self, val: Option<i64>) -> ConfigResult<Config> {
        Arc::get_mut(&mut self.proxy_conf).unwrap().set_timeout(val).map(|is_modified| {
            self.is_modified = is_modified;
            self
        })
    }

    fn set_one_time_auth(mut self, val: Option<bool>) -> ConfigResult<Config> {
        Arc::get_mut(&mut self.proxy_conf)
            .unwrap()
            .set_one_time_auth(val)
            .map(|is_modified| {
                self.is_modified = is_modified;
                self
            })
    }
}

fn check_and_set_from_toml(tbl: &Table, mut conf: Config) -> ConfigResult<Config> {
    macro_rules! try_set {
        ($set:ident, $name:expr, str) => { try_set!($set, $name, Value::as_str) };
        ($set:ident, $name:expr, int) => { try_set!($set, $name, Value::as_integer) };
        ($set:ident, $name:expr, bool) => { try_set!($set, $name, Value::as_bool) };
        ($set:ident, $name:expr, $f:path) => { conf = conf.$set(tbl.get($name).and_then($f))?; };
    }

    try_set!(set_quiet, "quiet", int);
    try_set!(set_verbose, "verbose", int);
    try_set!(set_log_file, "log_file", str);
    try_set!(set_pid_file, "pid_file", str);
    try_set!(set_prefer_ipv6, "prefer_ipv6", bool);
    try_set!(set_mode, "mode", str);

    try_set!(set_address, "address", str);
    try_set!(set_port, "port", int);
    try_set!(set_method, "method", str);
    try_set!(set_password, "password", str);
    try_set!(set_timeout, "timeout", int);
    try_set!(set_one_time_auth, "one_time_auth", bool);
    Ok(conf)
}

fn check_and_set_from_args(args: &ArgMatches, mut conf: Config) -> ConfigResult<Config> {
    macro_rules! try_set {
        ($set:ident, $name:expr, str) => {
            try_set!($set, args.value_of($name))
        };
        ($set:ident, $name:expr, bool) => {
            try_set!($set, Some(args.is_present($name)))
        };
        ($set:ident, $name:expr, int) => {{
            if let Some(v) = args.value_of($name) {
                match v.parse::<i64>() {
                    Ok(v) => try_set!($set, Some(v)),
                    Err(_) => return Err(ConfigError::InvalidNumber(v.to_string())),
                }
            }
        }};
        ($set:ident, $name:expr, occurrences) => {
            try_set!($set, Some(args.occurrences_of($name) as i64))
        };
        ($set:ident, $val:expr) => { conf = conf.$set($val)?; };
    }

    try_set!(set_quiet, "quiet", occurrences);
    try_set!(set_verbose, "verbose", occurrences);
    try_set!(set_log_file, "log_file", str);
    try_set!(set_pid_file, "pid_file", str);
    try_set!(set_prefer_ipv6, "prefer_ipv6", bool);
    try_set!(set_mode, "mode", str);

    try_set!(set_address, "address", str);
    try_set!(set_port, "port", int);
    try_set!(set_method, "method", str);
    try_set!(set_password, "password", str);
    try_set!(set_timeout, "timeout", int);
    try_set!(set_one_time_auth, "one_time_auth", bool);
    Ok(conf)
}

fn check_and_set_servers(servers: &[Value], mut conf: Config) -> ConfigResult<Config> {
    let mut server_confs = vec![];

    for server in servers {
        match *server {
            Value::Table(ref tbl) => {
                let mut server_conf = conf.proxy_conf.clone();

                {
                    let mut tmp = Arc::make_mut(&mut server_conf);

                    if !tbl.contains_key("address") {
                        return Err(ConfigError::MissServerAddress);
                    }
                    if !tbl.contains_key("port") {
                        return Err(ConfigError::MissServerPort);
                    }

                    tmp.set_address(tbl.get("address").and_then(Value::as_str))?;
                    tmp.set_port(tbl.get("port").and_then(Value::as_integer))?;

                    tmp.set_method(tbl.get("method").and_then(Value::as_str))?;
                    tmp.set_password(tbl.get("password").and_then(Value::as_str))?;
                    tmp.set_timeout(tbl.get("timeout").and_then(Value::as_integer))?;
                    tmp.set_one_time_auth(tbl.get("one_time_auth").and_then(Value::as_bool))?;
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
    Ok(conf)
}

fn check_and_set_server_from_args(args: &ArgMatches, mut conf: Config) -> ConfigResult<Config> {
    let password = args.value_of("password").ok_or(ConfigError::MissServerPassword)?;
    let method = args.value_of("method").ok_or(ConfigError::MissServerMethod)?;

    let server_address = args.value_of("server").unwrap();
    let mut port_addr: Vec<&str> = server_address.rsplitn(2, ':').collect();
    if port_addr.len() == 2 {
        let addr = port_addr.pop().unwrap();
        let port = port_addr.pop().unwrap();
        let port = port.parse::<i64>().map_err(|_| ConfigError::InvalidNumber(port.to_string()))?;

        let mut server_conf = ProxyConfig::default();
        server_conf.set_address(Some(addr))?;
        server_conf.set_port(Some(port))?;

        server_conf.set_method(Some(method))?;
        server_conf.set_password(Some(password))?;
        server_conf.set_one_time_auth(Some(args.is_present("one_time_auth")))?;

        if let Some(t) = args.value_of("timeout") {
            let t = t.parse::<i64>().map_err(|_| ConfigError::InvalidNumber(t.to_string()))?;
            server_conf.set_timeout(Some(t))?;
        }

        conf.server_confs = Some(vec![Arc::new(server_conf)]);
        Ok(conf)
    } else {
        Err(ConfigError::InvalidAddress(server_address.to_string()))
    }
}

// TODO: change to use macro when https://github.com/kbknapp/clap-rs/pull/731 decided
fn parse_cmds<'a>() -> ArgMatches<'a> {
    let name = if cfg!(feature = "sslocal") {
        "sslocal"
    } else {
        "ssserver"
    };
    let mut args = App::new(name)
        .version("0.6.0")
        .arg(Arg::with_name("config")
            .short("c")
            .value_name("config")
            .help("path to config file")
            .takes_value(true))
        .arg(Arg::with_name("password")
            .short("k")
            .value_name("password")
            .help("password")
            .takes_value(true))
        .arg(Arg::with_name("method")
            .short("m")
            .value_name("method")
            .help("encryption method"))
        .arg(Arg::with_name("timeout")
            .short("t")
            .value_name("timeout")
            .help("timeout in seconds [default: 60]"))
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .multiple(true)
            .help("sets the level of verbosity"))
        .arg(Arg::with_name("quiet")
            .short("q")
            .long("quiet")
            .multiple(true)
            .help("quiet mode, only show warnings/errors"))
        .arg(Arg::with_name("log_file")
            .long("log-file")
            .value_name("path")
            .help("log file for daemon mode")
            .takes_value(true))
        .arg(Arg::with_name("address")
            .short("a")
            .value_name("address")
            .help("binding address"))
        .arg(Arg::with_name("port")
            .short("p")
            .value_name("port")
            .help("bind port"))
        .arg(Arg::with_name("one_time_auth")
            .short("o")
            .long("one-time-auth")
            .help("enable one time auth"))
        .arg(Arg::with_name("prefer_ipv6")
            .long("prefer-ipv6")
            .help("priority use IPv6"));

    if cfg!(target_family = "unix") {
        args = args.arg(Arg::with_name("daemon")
                .short("d")
                .help("daemon mode")
                .takes_value(true)
                .possible_values(&["start", "stop", "restart"]))
            .arg(Arg::with_name("pid_file")
                .long("pid-file")
                .value_name("path")
                .help("pid file for daemon mode")
                .takes_value(true));
    }

    if cfg!(feature = "sslocal") {
        args = args.arg(Arg::with_name("server")
                .short("s")
                .value_name("ip:port")
                .help("server address and port")
                .takes_value(true))
            .arg(Arg::with_name("mode")
                .long("mode")
                .help("the way to choose server"));
    }

    args.get_matches()
}

fn read_config(config_path: &str) -> Result<Table, ConfigError> {
    let mut f = File::open(config_path).map_err(|e| {
            let errmsg = format!("config file {} does not exists ({})", config_path, e);
            ConfigError::OpenFileFailed(errmsg)
        })?;

    let mut input = String::new();
    f.read_to_string(&mut input)
        .map_err(|e| {
            let errmsg = format!("config file {} is not valid UTF-8 file ({})",
                                 config_path,
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

// values from command line will override values from config file.
// if `server` is present in command line, then override `servers`.
pub fn gen_config() -> Result<Arc<Config>, ConfigError> {
    let mut conf = Config::default();
    let args = parse_cmds();

    match args.value_of("config").map(read_config) {
        Some(Ok(tbl)) => {
            conf = check_and_set_from_toml(&tbl, conf)?;
            conf = check_and_set_from_args(&args, conf)?;

            if cfg!(feature = "sslocal") {
                if args.value_of("server").is_some() {
                    conf = check_and_set_server_from_args(&args, conf)?;
                } else {
                    let servers = tbl.get("servers").and_then(Value::as_slice);
                    if let Some(servers) = servers {
                        conf = check_and_set_servers(servers, conf)?;
                    } else {
                        return Err(ConfigError::MissServerAddress);
                    }
                }
            }
        }
        None => {
            if cfg!(feature = "sslocal") {
                if args.value_of("server").is_some() {
                    conf = check_and_set_server_from_args(&args, conf)?;
                } else {
                    return Err(ConfigError::MissServerAddress);
                }
            }

            conf = check_and_set_from_args(&args, conf)?;
        }
        Some(Err(e)) => return Err(e),
    }

    // init daemonize if need
    let daemon = match args.value_of("daemon") {
        Some("stop") => my_daemonize::Cmd::Stop,
        Some("start") => my_daemonize::Cmd::Start,
        Some("restart") => my_daemonize::Cmd::Restart,
        None => my_daemonize::Cmd::Unknown,
        Some(cmd) => {
            let errmsg = format!("invalid daemon command: {}", cmd);
            return Err(ConfigError::Other(errmsg));
        }
    };

    if daemon != my_daemonize::Cmd::Unknown {
        if conf.pid_file.is_none() {
            conf.pid_file = Some(conf.default_pid_file());
        }
        if conf.log_file.is_none() {
            conf.log_file = Some(conf.default_log_file());
        }
    }

    my_logger::init(conf.log_level, conf.log_file.as_ref()).map_err(|e| {
            let errmsg = format!("init logger failed: {}", e);
            ConfigError::Other(errmsg)
        })?;

    // must daemonize after init logger
    if daemon != my_daemonize::Cmd::Unknown {
        my_daemonize::init(daemon, conf.pid_file.as_ref().unwrap());
    }

    Ok(Arc::new(conf))
}

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
