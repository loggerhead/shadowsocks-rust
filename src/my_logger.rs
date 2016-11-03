use std::io;
use std::fmt;
use std::error::Error;
use std::fs::OpenOptions;

use chrono::Local;
use slog;
use slog_term;
use slog_stream;
use slog_stdlog;
use slog::Level;
use slog::DrainExt;

use config::Config;

macro_rules! now {
    () => ( Local::now().format("%m-%d %H:%M:%S%.3f") )
}

macro_rules! setup_global_logger {
    ($lv:expr, $drain:expr) => (
        let d = slog::level_filter($lv, $drain).fuse();
        let logger = slog::Logger::root(d, o!());
        slog_stdlog::set_logger(logger).unwrap();
    )
}

pub fn init(conf: &Config) -> Result<(), LoggerInitError> {
    let log_level = if let Some(v) = conf.get_i64("verbose") {
        match v {
            1 => Level::Debug,
            _ => Level::Trace,
        }
    } else if let Some(v) = conf.get_i64("quiet") {
        match v {
            1 => Level::Warning,
            2 => Level::Error,
            _ => Level::Critical,
        }
    } else {
        Level::Info
    };

    if let Some(v) = conf.get("log_file") {
        let log_path = v.as_str().unwrap();
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(log_path);

        match f {
            Ok(file) => {
                let streamer = slog_stream::stream(file, MyFormat);
                setup_global_logger!(log_level, streamer);
            }
            Err(_) => {
                let errmsg = format!("cannot open log file {}", log_path);
                return Err(LoggerInitError::new(errmsg));
            }
        }
    } else {
        let drain = slog_term::StreamerBuilder::new()
            .use_custom_timestamp(move |io| write!(io, "{}", now!()))
            .build();
        setup_global_logger!(log_level, drain);
    }

    Ok(())
}


struct MyFormat;

impl slog_stream::Format for MyFormat {
    fn format(&self,
              io: &mut io::Write,
              rinfo: &slog::Record,
              _logger_values: &slog::OwnedKeyValueList)
              -> io::Result<()> {
        let msg = format!("{} {} - {}\n", now!(), rinfo.level(), rinfo.msg());
        io.write_all(msg.as_bytes()).map(|_| ())
    }
}

#[derive(Debug)]
pub struct LoggerInitError {
    desc: String,
}

impl LoggerInitError {
    fn new(desc: String) -> LoggerInitError {
        LoggerInitError { desc: desc }
    }
}

impl fmt::Display for LoggerInitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.desc)
    }
}

impl Error for LoggerInitError {
    fn description(&self) -> &str {
        &self.desc
    }
}
