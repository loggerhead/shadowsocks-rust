extern crate log;

use std::fmt;
use std::sync::Mutex;
use std::error::Error;
use std::io::prelude::*;
use std::fs::{File, OpenOptions};

use chrono::Local;
use log::{LogRecord, LogLevel, LogMetadata, LogLevelFilter};

use config::Config;

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

enum OutputType {
    None,
    Stdout,
    File(Mutex<File>),
}

struct MyLogger {
    log_level: LogLevel,
    output_type: OutputType,
}

impl MyLogger {
    fn new(log_level: LogLevel, output_type: OutputType) -> Self {
        MyLogger {
            log_level: log_level,
            output_type: output_type,
        }
    }
}

impl log::Log for MyLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= self.log_level
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            let dt = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
            let msg = format!("{} - {:5} - {}\n", dt, record.level(), record.args());
            match self.output_type {
                OutputType::None => {}
                OutputType::Stdout => {
                    print!("{}", msg);
                }
                OutputType::File(ref f) => {
                    let _ = f.lock().unwrap().write_all(msg.as_bytes());
                    let _ = f.lock().unwrap().flush();
                }
            }
        }
    }
}

pub fn init(conf: &Config) -> Result<(), LoggerInitError> {
    let log_level_filter = if let Some(v) = conf.get_i64("verbose") {
        match v {
            1 => LogLevelFilter::Debug,
            _ => LogLevelFilter::Trace,
        }
    } else if let Some(v) = conf.get_i64("quiet") {
        match v {
            1 => LogLevelFilter::Warn,
            2 => LogLevelFilter::Error,
            _ => LogLevelFilter::Off,
        }
    } else {
        LogLevelFilter::Info
    };

    let output_type = if let Some(v) = conf.get("log_file") {
        let log_path = v.as_str().unwrap();
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(log_path);
        match f {
            Ok(f) => OutputType::File(Mutex::new(f)),
            Err(_) => {
                let errmsg = format!("cannot open log file {}", log_path);
                return Err(LoggerInitError::new(errmsg));
            }
        }
    } else {
        OutputType::Stdout
    };

    log::set_logger(|max_log_level| {
            max_log_level.set(log_level_filter);
            let my_logger = match log_level_filter.to_log_level() {
                Some(log_level) => MyLogger::new(log_level, output_type),
                _ => MyLogger::new(LogLevel::Error, OutputType::None),
            };
            Box::new(my_logger)
        })
        .map_err(|e| LoggerInitError::new(e.description().to_string()))
}