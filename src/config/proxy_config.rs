use std::fmt;
use std::str;

use rand::{Rng, thread_rng};
use rustc_serialize::base64::{ToBase64, FromBase64, STANDARD};

use crypto::Method;
use network::{is_ip, is_hostname};
use super::{ConfigError, ConfigResult};

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct ProxyConfig {
    pub address: String,
    pub port: u16,
    pub method: Method,
    pub password: String,
    pub timeout: u16,
    pub one_time_auth: bool,
}

impl fmt::Display for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "address = \"{}\"\n\
                port = {}\n\
                method = \"{}\"\n\
                password = \"{}\"\n\
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

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
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
    pub fn base64_encode(&self) -> String {
        // aes-256-ctr:foo@example.com:8888
        let encoded = format!("{}:{}@{}:{}",
                              self.method,
                              self.password,
                              self.address,
                              self.port);
        format!("ss://{}", encoded.as_bytes().to_base64(STANDARD))
    }

    pub fn base64_decode(&mut self, s: &str) -> ConfigResult<()> {
        if s.starts_with("ss://") {
            let s = &s[5..].from_base64()
                .map_err(|_| ConfigError::Other(format!("decode config failed: {}", s)))?;
            let s =
                str::from_utf8(s).or(Err(ConfigError::Other("decode config failed: invalid UTF-8 chars"
                        .to_string())))?;

            let parts: Vec<&str> = s.rsplitn(2, '@').collect();
            let port_address: Vec<&str> = parts[0].rsplitn(2, ':').collect();
            let method_password: Vec<&str> = parts[1].splitn(2, ':').collect();

            self.method = method_password[0].parse::<Method>()
                .map_err(|_| ConfigError::InvalidMethod(method_password[0].to_string()))?;
            self.password = method_password[1].to_string();
            self.address = port_address[1].to_string();
            self.port = port_address[0].parse::<u16>()
                .map_err(|_| ConfigError::InvalidNumber(port_address[0].to_string()))?;
            Ok(())
        } else {
            Err(ConfigError::Other(format!("decode config failed: {}", s)))
        }
    }

    pub fn set_address(&mut self, val: Option<&str>) -> ConfigResult<()> {
        if let Some(v) = val {
            if !(is_ip(v) || is_hostname(v)) {
                return Err(ConfigError::InvalidAddress(v.to_string()));
            } else {
                self.address = v.to_string();
            }
        }
        Ok(())
    }

    pub fn set_port(&mut self, val: Option<i64>) -> ConfigResult<()> {
        if let Some(v) = val {
            if v < 0 || (u16::max_value() as i64) < v {
                return Err(ConfigError::OutOfRange(v));
            } else {
                self.port = v as u16;
            }
        }
        Ok(())
    }

    pub fn set_method(&mut self, val: Option<&str>) -> ConfigResult<()> {
        if let Some(v) = val {
            let method = v.parse::<Method>()
                .map_err(|_| ConfigError::InvalidMethod(v.to_string()))?;
            self.method = method;
        }
        Ok(())
    }

    pub fn set_password(&mut self, val: Option<&str>) -> ConfigResult<()> {
        if let Some(v) = val {
            self.password = v.to_string();
        }
        Ok(())
    }

    pub fn set_timeout(&mut self, val: Option<i64>) -> ConfigResult<()> {
        if let Some(v) = val {
            if v < 0 {
                return Err(ConfigError::OutOfRange(v));
            } else {
                self.timeout = v as u16;
            }
        }
        Ok(())
    }

    pub fn set_one_time_auth(&mut self, val: Option<bool>) -> ConfigResult<()> {
        if let Some(v) = val {
            self.one_time_auth = v;
        }
        Ok(())
    }
}
