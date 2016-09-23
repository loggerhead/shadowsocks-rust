use rand::{Rng, OsRng};
use crypto::md5::Md5;
use crypto::digest::Digest;
use crypto::aes::{ctr, KeySize};
use crypto::symmetriccipher::SynchronousStreamCipher;

type Cipher = Box<SynchronousStreamCipher + 'static>;

fn create_cipher(key: &[u8], iv: &[u8]) -> Cipher {
    Box::new(ctr(KeySize::KeySize256, key, iv))
}

// equivalent to OpenSSL's EVP_BytesToKey() with count 1
fn gen_key_iv(password: &str, key_len: usize, iv_len: usize) -> (Vec<u8>, Vec<u8>) {
    let mut i = 0;
    let mut m: Vec<Box<[u8; 16]>> = vec![];
    let mut data = vec![];
    data.extend_from_slice(password.as_bytes());

    while m.len() < key_len + iv_len {
        if i > 0 {
            data.clear();
            data.extend_from_slice(&*m[i - 1]);
            data.extend_from_slice(password.as_bytes());
        };

        let mut buf = Box::new([0u8; 16]);
        let mut md5 = Md5::new();
        md5.input(&data);
        md5.result(&mut *buf);
        m.push(buf);
        i += 1;
    }

    let mut tmp = vec![];
    for bytes in m {
        let bytes = &*bytes;
        tmp.extend_from_slice(&*bytes);
    }

    let mut key = vec![];
    let mut iv = vec![];
    key.extend_from_slice(&tmp[..key_len]);
    iv.extend_from_slice(&tmp[key_len..key_len + iv_len]);

    (key, iv)
}

macro_rules! process {
    ($cipher:expr, $data:expr) => (
        {
            let mut output = vec![0u8; $data.len()];
            match *($cipher) {
                Some(ref mut cipher) => {
                    cipher.process($data, output.as_mut_slice());
                    Some(output)
                }
                _ => None
            }
        }
    );
}

pub struct Encryptor {
    is_iv_sent: bool,
    key: Vec<u8>,
    cipher_iv: Vec<u8>,
    decipher_iv: Vec<u8>,
    cipher: Option<Cipher>,
    decipher: Option<Cipher>,
}

// First packet format:
//
// +-----------+----------------+
// | cipher iv | encrypted data |
// +-----------+----------------+
//       16
impl Encryptor {
    pub fn new(password: &str) -> Encryptor {
        let (key, _iv) = gen_key_iv(password, 256, 32);
        let mut cipher_iv = vec![0u8; 16];
        let _ = OsRng::new().map(|mut rng| rng.fill_bytes(&mut cipher_iv));
        let cipher = create_cipher(&key, &cipher_iv);

        Encryptor {
            is_iv_sent: false,
            key: key,
            cipher_iv: cipher_iv,
            decipher_iv: vec![0u8; 16],
            cipher: Some(cipher),
            decipher: None,
        }
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let mut encrypted = process!(&mut self.cipher, data);

        if self.is_iv_sent {
            encrypted
        } else {
            self.is_iv_sent = true;

            match encrypted {
                Some(ref mut encrypted) => {
                    let mut result = vec![];
                    result.extend_from_slice(&self.cipher_iv);
                    result.append(encrypted);

                    Some(result)
                }
                _ => None,
            }
        }
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if self.decipher.is_none() {
            if data.len() < 16 {
                return None;
            }

            let offset = self.decipher_iv.len();
            self.decipher_iv.copy_from_slice(&data[..offset]);
            self.decipher = Some(create_cipher(&self.key, &self.decipher_iv));

            process!(&mut self.decipher, &data[offset..])
        } else {
            process!(&mut self.decipher, data)
        }
    }
}

#[cfg(test)]
mod test {
    use std::str;
    use std::thread;
    use std::io::prelude::*;
    use std::sync::mpsc::channel;
    use std::net::{TcpListener, TcpStream, Shutdown};

    use encrypt::Encryptor;

    const PASSWORD: &'static str = "foo";
    const MESSAGES: &'static [&'static str] = &["a", "hi", "foo", "hello", "world"];

    macro_rules! encrypt {
        ($encryptor:expr, $data:expr) => (
            {
                let encrypted = $encryptor.encrypt($data);
                assert!(encrypted.is_some());
                encrypted.unwrap()
            }
        );
    }

    macro_rules! decrypt {
        ($encryptor:expr, $data:expr) => (
            {
                let decrypted = $encryptor.decrypt($data);
                assert!(decrypted.is_some());
                decrypted.unwrap()
            }
        );
    }

    #[test]
    fn in_order() {
        let mut encryptor = Encryptor::new(PASSWORD);
        for msg in MESSAGES.iter() {
            let encrypted = encrypt!(encryptor, msg.as_bytes());
            let decrypted = decrypt!(encryptor, &encrypted);
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
                let decrypted = decrypt!(encryptor, &buf_encrypted);
                assert_eq!(buf_msg[..], decrypted[..]);
                buf_msg.clear();
                buf_encrypted.clear();
            );
        }

        for i in 0..MESSAGES.len() {
            let msg = MESSAGES[i].as_bytes();
            let encrypted = encrypt!(encryptor, msg);

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

        macro_rules! test_encryptor {
            ($stream:expr, $encryptor:expr) => (
                {
                    for msg in MESSAGES.iter() {
                        let encrypted = encrypt!($encryptor, msg.as_bytes());
                        $stream.write(&encrypted).unwrap();
                    }
                    $stream.shutdown(Shutdown::Write).unwrap();

                    let mut data = vec![];
                    $stream.read_to_end(&mut data).unwrap();
                    let decrypted = decrypt!($encryptor, &data);

                    let mut tmp = vec![];
                    for msg in MESSAGES.iter() {
                        tmp.extend_from_slice(msg.as_bytes());
                    }
                    let messages_bytes = &tmp;
                    assert_eq!(messages_bytes, &decrypted);
                }
            );
        }

        let t1 = thread::spawn(move || {
            let mut encryptor = Encryptor::new(PASSWORD);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            let mut stream = listener.incoming().next().unwrap().unwrap();
            test_encryptor!(stream, encryptor);
        });

        let t2 = thread::spawn(move || {
            let mut encryptor = Encryptor::new(PASSWORD);
            let server_addr = rx.recv().unwrap();
            let mut stream = TcpStream::connect(server_addr).unwrap();
            test_encryptor!(stream, encryptor);
        });

        t1.join().unwrap();
        t2.join().unwrap();
    }
}
