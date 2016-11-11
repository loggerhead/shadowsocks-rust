extern crate shadowsocks;

use std::str;
use std::thread;
use std::io::prelude::*;
use std::sync::mpsc::channel;
use std::net::{TcpListener, TcpStream, Shutdown};

use shadowsocks::crypto::Encryptor;

const PASSWORD: &'static str = "foo";
const MESSAGES: &'static [&'static str] = &["a", "hi", "foo", "hello", "world"];

#[cfg(not(feature = "openssl"))]
const METHODS: &'static [&'static str] = &[
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "rc4",
    "hc128",
    "salsa20",
    "xsalsa20",
    "chacha20",
    "xchacha20",
    "sosemanuk",
];

#[cfg(feature = "openssl")]
const METHODS: &'static [&'static str] = &[
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "rc4",
    "hc128",
    "salsa20",
    "xsalsa20",
    "chacha20",
    "xchacha20",
    "sosemanuk",
    "aes-128-cfb",
    "aes-256-cfb",
    "aes-128-cfb1",
    "aes-256-cfb1",
    "aes-128-cfb8",
    "aes-256-cfb8",
];

macro_rules! assert_new {
    ($method:expr) => (
        {
            let encryptor = Encryptor::new(PASSWORD, $method);
            match encryptor {
                Ok(encryptor) => encryptor,
                Err(e) => {
                    println!("create encryptor failed: {:?}", e);
                    return assert!(false);
                }
            }
        }
    )
}

macro_rules! assert_do {
    ($cryptor:expr, $func:tt, $data:expr) => (
        {
            let processed = $cryptor.$func($data);
            assert!(processed.is_some());
            processed.unwrap()
        }
    )
}

macro_rules! assert_raw_encrypt {
    ($cryptor:expr, $data:expr) => ( assert_do!($cryptor, raw_encrypt, $data) )
}

macro_rules! assert_raw_decrypt {
    ($cryptor:expr, $data:expr) => ( assert_do!($cryptor, raw_decrypt, $data) )
}

macro_rules! assert_encrypt {
    ($cryptor:expr, $data:expr) => ( assert_do!($cryptor, encrypt, $data) )
}

macro_rules! assert_decrypt {
    ($cryptor:expr, $data:expr) => ( assert_do!($cryptor, decrypt, $data) )
}

macro_rules! assert_encrypt_udp {
    ($cryptor:expr, $data:expr) => ( assert_do!($cryptor, encrypt_udp, $data) )
}

macro_rules! assert_decrypt_udp {
    ($cryptor:expr, $data:expr) => ( assert_do!($cryptor, decrypt_udp, $data) )
}

#[test]
fn in_order() {
    for method in METHODS {
        let mut encryptor = assert_new!(method);
        for msg in MESSAGES {
            let encrypted = assert_encrypt!(encryptor, msg.as_bytes());
            let decrypted = assert_decrypt!(encryptor, &encrypted);
            assert_eq!(msg.as_bytes()[..], decrypted[..]);
        }
    }
}

#[test]
fn chaos() {
    for method in METHODS {
        let mut encryptor = assert_new!(method);
        let mut buf_msg = vec![];
        let mut buf_encrypted = vec![];

        for i in 0..MESSAGES.len() {
            let msg = MESSAGES[i].as_bytes();
            let encrypted = assert_encrypt!(encryptor, msg);

            buf_msg.extend_from_slice(msg);
            buf_encrypted.extend_from_slice(&encrypted);
            if i % 2 == 0 {
                let decrypted = assert_decrypt!(encryptor, &buf_encrypted);
                assert_eq!(buf_msg[..], decrypted[..]);
                buf_msg.clear();
                buf_encrypted.clear();
            }
        }

        let decrypted = assert_decrypt!(encryptor, &buf_encrypted);
        assert_eq!(buf_msg[..], decrypted[..]);
        buf_msg.clear();
        buf_encrypted.clear();
    }
}

#[test]
fn tcp_server() {
    fn test_encryptor(mut stream: TcpStream, mut encryptor: Encryptor) {
        for msg in MESSAGES.iter() {
            let encrypted = assert_encrypt!(encryptor, msg.as_bytes());
            stream.write(&encrypted).unwrap();
        }
        stream.shutdown(Shutdown::Write).unwrap();

        let mut data = vec![];
        stream.read_to_end(&mut data).unwrap();
        let decrypted = assert_decrypt!(encryptor, &data);

        let mut msgs = vec![];
        for msg in MESSAGES.iter() {
            msgs.extend_from_slice(msg.as_bytes());
        }
        assert_eq!(&msgs, &decrypted);
    }


    for method in METHODS {
        let (tx, rx) = channel();

        let t1 = thread::spawn(move || {
            let encryptor = assert_new!(method);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            let stream = listener.incoming().next().unwrap().unwrap();
            test_encryptor(stream, encryptor);
        });

        let t2 = thread::spawn(move || {
            let encryptor = assert_new!(method);
            let server_addr = rx.recv().unwrap();
            let stream = TcpStream::connect(server_addr).unwrap();
            test_encryptor(stream, encryptor);
        });

        t1.join().unwrap();
        t2.join().unwrap();
    }
}

#[test]
fn udp() {
    for method in METHODS {
        let mut encryptor = assert_new!(method);
        for msg in MESSAGES {
            let encrypted = assert_encrypt_udp!(encryptor, msg.as_bytes());
            let decrypted = assert_decrypt_udp!(encryptor, &encrypted);
            assert_eq!(msg.as_bytes()[..], decrypted[..]);
        }
    }
}
