use rand::{Rng, OsRng};
use crypto::md5::Md5;
use crypto::digest::Digest;
use crypto::aes::{ctr, KeySize};
use crypto::symmetriccipher::SynchronousStreamCipher;

type Cipher = Box<SynchronousStreamCipher + 'static>;

pub struct Encryptor {
    is_iv_sent: bool,
    key: Vec<u8>,
    password: String,
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
        let (key, cipher_iv) = gen_key_iv(password);
        let cipher = create_cipher(&key, &cipher_iv);

        Encryptor {
            is_iv_sent: false,
            key: key,
            password: String::from(password),
            cipher_iv: cipher_iv,
            decipher_iv: vec![0u8; 16],
            cipher: Some(cipher),
            decipher: None,
        }
    }

    pub fn get_key(&self) -> &Vec<u8> {
        &self.key
    }

    pub fn get_iv(&self) -> &Vec<u8> {
        &self.cipher_iv
    }

    // TODO: use Cow instead
    fn process(&mut self, data: &[u8], is_encrypt: bool) -> Option<Vec<u8>> {
        let mut output = vec![0u8; data.len()];

        let mut cipher = if is_encrypt {
            self.cipher.take().unwrap()
        } else {
            self.decipher.take().unwrap()
        };

        cipher.process(data, output.as_mut_slice());

        if is_encrypt {
            self.cipher = Some(cipher);
        } else {
            self.decipher = Some(cipher);
        }

        Some(output)
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let mut encrypted = self.process(data, true);

        if self.is_iv_sent {
            encrypted
        } else {
            self.is_iv_sent = true;

            match encrypted {
                Some(ref mut encrypted) => {
                    let len = self.cipher_iv.len() + encrypted.len();
                    let mut result = Vec::with_capacity(len);
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
            self.decipher_iv[..].copy_from_slice(&data[..offset]);
            self.decipher = Some(create_cipher(&self.key, &self.decipher_iv));

            self.process(&data[offset..], false)
        } else {
            self.process(data, false)
        }
    }

    pub fn encrypt_udp(&self, data: &[u8]) -> Option<Vec<u8>> {
        let (key, cipher_iv) = gen_key_iv(&self.password);
        let mut cipher = create_cipher(&key, &cipher_iv);

        let mut encrypted = vec![0u8; data.len()];
        cipher.process(data, encrypted.as_mut_slice());

        let mut res = Vec::with_capacity(cipher_iv.len() + data.len());
        res.extend_from_slice(&cipher_iv);
        res.extend_from_slice(&encrypted);

        Some(res)
    }

    pub fn decrypt_udp(&self, data: &[u8]) -> Option<Vec<u8>> {
        let (key, iv) = gen_key_iv(&self.password);
        let iv_len = iv.len();
        let decipher_iv = &data[..iv_len];

        let mut decipher = create_cipher(&key, &decipher_iv);
        let mut decrypted = vec![0u8; data.len() - iv_len];
        decipher.process(&data[iv_len..], decrypted.as_mut_slice());

        Some(decrypted)
    }
}

fn create_cipher(key: &[u8], iv: &[u8]) -> Cipher {
    Box::new(ctr(KeySize::KeySize256, key, iv))
}

// TODO: cache key
fn gen_key_iv(password: &str) -> (Vec<u8>, Vec<u8>) {
    let (key, _iv) = evp_bytes_to_key(password, 32, 16);
    let mut cipher_iv = Vec::with_capacity(16);
    unsafe { cipher_iv.set_len(16); }
    let _ = OsRng::new().map(|mut rng| rng.fill_bytes(&mut cipher_iv));
    (key, cipher_iv)
}

// equivalent to OpenSSL's EVP_BytesToKey() with count 1
fn evp_bytes_to_key(password: &str, key_len: usize, iv_len: usize) -> (Vec<u8>, Vec<u8>) {
    let mut i = 0;
    let mut m: Vec<Box<[u8; 16]>> = Vec::with_capacity(key_len + iv_len);
    let password = password.as_bytes();
    let mut data = Vec::with_capacity(16 + password.len());
    let mut cnt = 0;

    while cnt < key_len + iv_len {
        unsafe { data.set_len(0); }
        if i > 0 {
            data.extend_from_slice(&*m[i - 1]);
        }
        data.extend_from_slice(password);

        let mut buf = Box::new([0u8; 16]);
        let mut md5 = Md5::new();
        md5.input(&data);
        md5.result(&mut *buf);
        cnt += buf.len();

        m.push(buf);
        i += 1;
    }

    let mut tmp: Vec<u8> = Vec::with_capacity(16 * m.capacity());
    for bytes in m {
        tmp.extend_from_slice(&*bytes);
    }

    let key = Vec::from(&tmp[..key_len]);
    let iv = Vec::from(&tmp[key_len..key_len + iv_len]);

    (key, iv)
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
        for msg in MESSAGES.iter() {
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
            );
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
}
