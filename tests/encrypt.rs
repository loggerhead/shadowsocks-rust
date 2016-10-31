extern crate shadowsocks;

use std::str;
use std::thread;
use std::io::prelude::*;
use std::sync::mpsc::channel;
use std::net::{TcpListener, TcpStream, Shutdown};

use shadowsocks::encrypt::Encryptor;

const PASSWORD: &'static str = "foo";
const MESSAGES: &'static [&'static str] = &["a", "hi", "foo", "hello", "world"];

fn encrypt(cryptor: &mut Encryptor, data: &[u8]) -> Vec<u8> {
    let encrypted = cryptor.encrypt(data);
    assert!(encrypted.is_some());
    encrypted.unwrap()
}

fn decrypt(cryptor: &mut Encryptor, data: &[u8]) -> Vec<u8> {
    let decrypted = cryptor.decrypt(data);
    assert!(decrypted.is_some());
    decrypted.unwrap()
}

#[test]
fn in_order() {
    let mut encryptor = Encryptor::new(PASSWORD);
    for msg in MESSAGES {
        let encrypted = encrypt(&mut encryptor, msg.as_bytes());
        let decrypted = decrypt(&mut encryptor, &encrypted);
        assert_eq!(msg.as_bytes()[..], decrypted[..]);
    }
}

#[test]
fn chaos() {
    let mut encryptor = Encryptor::new(PASSWORD);
    let mut buf_msg = vec![];
    let mut buf_encrypted = vec![];

    macro_rules! assert_decrypt {
        () => (
            let decrypted = decrypt(&mut encryptor, &buf_encrypted);
            assert_eq!(buf_msg[..], decrypted[..]);
            buf_msg.clear();
            buf_encrypted.clear();
        )
    }

    for i in 0..MESSAGES.len() {
        let msg = MESSAGES[i].as_bytes();
        let encrypted = encrypt(&mut encryptor, msg);

        buf_msg.extend_from_slice(msg);
        buf_encrypted.extend_from_slice(&encrypted);
        if i % 2 == 0 {
            assert_decrypt!();
        }
    }
    assert_decrypt!();
}

#[test]
fn tcp_server() {
    let (tx, rx) = channel();

    fn test_encryptor(mut stream: TcpStream, mut encryptor: Encryptor) {
        for msg in MESSAGES.iter() {
            let encrypted = encrypt(&mut encryptor, msg.as_bytes());
            stream.write(&encrypted).unwrap();
        }
        stream.shutdown(Shutdown::Write).unwrap();

        let mut data = vec![];
        stream.read_to_end(&mut data).unwrap();
        let decrypted = decrypt(&mut encryptor, &data);

        let mut tmp = vec![];
        for msg in MESSAGES.iter() {
            tmp.extend_from_slice(msg.as_bytes());
        }
        let messages_bytes = &tmp;
        assert_eq!(messages_bytes, &decrypted);
    }

    let t1 = thread::spawn(move || {
        let encryptor = Encryptor::new(PASSWORD);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        tx.send(listener.local_addr().unwrap()).unwrap();
        let stream = listener.incoming().next().unwrap().unwrap();
        test_encryptor(stream, encryptor);
    });

    let t2 = thread::spawn(move || {
        let encryptor = Encryptor::new(PASSWORD);
        let server_addr = rx.recv().unwrap();
        let stream = TcpStream::connect(server_addr).unwrap();
        test_encryptor(stream, encryptor);
    });

    t1.join().unwrap();
    t2.join().unwrap();
}

#[test]
fn udp() {
    fn encrypt_udp(cryptor: &mut Encryptor, data: &[u8]) -> Vec<u8> {
        let encrypted = cryptor.encrypt_udp(data);
        assert!(encrypted.is_some());
        encrypted.unwrap()
    }

    fn decrypt_udp(cryptor: &mut Encryptor, data: &[u8]) -> Vec<u8> {
        let decrypted = cryptor.decrypt_udp(data);
        assert!(decrypted.is_some());
        decrypted.unwrap()
    }

    let mut encryptor = Encryptor::new(PASSWORD);
    for msg in MESSAGES.iter() {
        let encrypted = encrypt_udp(&mut encryptor, msg.as_bytes());
        let decrypted = decrypt_udp(&mut encryptor, &encrypted);
        assert_eq!(msg.as_bytes()[..], decrypted[..]);
    }
}
