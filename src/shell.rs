use std::collections::BTreeMap;
use toml::{Parser, Value};


pub fn get_config() -> Option<BTreeMap<String, Value>> {
    let mut input = String::new();

    input = r#"
        servers = [
            "127.0.0.1:8388",
            "proxy.loggerhead.me:22"
        ]
        local_port = 8488
        password = "fuckGFW4times!"
        timeout = 300
        method = "aes-256-cfb"
    "#.to_string();

    let mut parser = Parser::new(&input);
    parser.parse()
}
