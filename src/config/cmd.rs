use std::sync::Arc;

use clap::{Arg, App, ArgMatches};

use super::{ConfigError, ConfigResult, ProxyConfig, Config};

// TODO: change to use macro when https://github.com/kbknapp/clap-rs/pull/731 decided
pub fn parse_cmds<'a>() -> ArgMatches<'a> {
    let name = if cfg!(feature = "sslocal") {
        "sslocal"
    } else {
        "ssserver"
    };
    let mut args = App::new(name)
        .version("0.6.0")
        .arg(Arg::with_name("input")
            .help("parse config from base64 encoded input")
            .takes_value(true))
        .arg(Arg::with_name("config")
            .short("c")
            .long("config")
            .value_name("path")
            .help("path to config file [default: ~/.shadowsocks/config.toml]")
            .takes_value(true))
        .arg(Arg::with_name("password")
            .short("k")
            .long("password")
            .value_name("str")
            .help("password")
            .takes_value(true))
        .arg(Arg::with_name("method")
            .short("m")
            .long("method")
            .value_name("str")
            .help("encryption method"))
        .arg(Arg::with_name("timeout")
            .short("t")
            .long("timeout")
            .value_name("int")
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
            .long("address")
            .value_name("str")
            .help("binding address"))
        .arg(Arg::with_name("port")
            .short("p")
            .long("port")
            .value_name("int")
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
                .long("daemon")
                .help("daemon mode")
                .value_name("str")
                .takes_value(true)
                .possible_values(&["start", "stop", "restart", "none"]))
            .arg(Arg::with_name("pid_file")
                .long("pid-file")
                .value_name("path")
                .help("pid file for daemon mode")
                .takes_value(true));
    }

    if cfg!(feature = "sslocal") {
        args = args.arg(Arg::with_name("server")
                .short("s")
                .long("server")
                .value_name("ip:port")
                .help("server address and port")
                .takes_value(true))
            .arg(Arg::with_name("mode")
                .long("mode")
                .takes_value(true)
                .value_name("str")
                .help("the way to choose server")
                .possible_values(&["fast", "balance"]))
            .arg(Arg::with_name("add_server")
                .long("add-server")
                .value_name("str")
                .takes_value(true)
                .help("append base64 encoded server config"));
    }

    args.get_matches()
}

pub fn check_and_set_from_args(args: &ArgMatches, conf: &mut Config) -> ConfigResult<()> {
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
        ($set:ident, $val:expr) => { conf.$set($val)?; };
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
    Ok(())
}

// `server` present in command line will override `servers`.
pub fn check_and_set_server_from_args(args: &ArgMatches, conf: &mut Config) -> ConfigResult<()> {
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
        Ok(())
    } else {
        Err(ConfigError::InvalidAddress(server_address.to_string()))
    }
}
