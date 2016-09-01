use crypto::md5::Md5;
use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::digest::Digest;
use crypto::aes::{ctr, KeySize};
use crypto::symmetriccipher::SynchronousStreamCipher;

use rand::{ Rng, OsRng };

type Cipher = Box<SynchronousStreamCipher + 'static>;

fn create_cipher(key: &[u8], iv: &[u8]) -> Cipher {
    Box::new(ctr(KeySize::KeySize256, &key, &iv))
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

fn hmac_md5(cipher_iv: &[u8], data: &[u8]) -> MacResult {
    let mut hmac = Hmac::new(Md5::new(), cipher_iv);
    hmac.input(data);

    hmac.result()
}

macro_rules! process {
    ($cipher:expr, $data:expr) => (
        {
            let mut output = vec![0u8; $data.len()];
            match $cipher {
                &mut Some(ref mut cipher) => {
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
    password_iv: Vec<u8>,
    cipher_iv: Vec<u8>,
    decipher_iv: Vec<u8>,
    cipher: Option<Cipher>,
    decipher: Option<Cipher>,
}

// First packet format:
//
// +----------------+-----------+------+
// | encrypted data | cipher iv | hmac |
// +----------------+-----------+------+
//                      16         16
impl Encryptor {
    pub fn new(password: &str) -> Encryptor {
        let (key, password_iv) = gen_key_iv(password, 256, 32);
        let mut cipher_iv = vec![0u8; 16];
        OsRng::new().unwrap().fill_bytes(&mut cipher_iv);
        let cipher = create_cipher(&key, &cipher_iv);

        Encryptor {
            is_iv_sent: false,
            key: key,
            password_iv: password_iv,
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
                    let mut result = vec![0u8; 16];
                    result.extend_from_slice(&self.cipher_iv);
                    result.append(encrypted);
                    let hmac = hmac_md5(&self.password_iv, &result[16..]);
                    &mut result[..16].copy_from_slice(hmac.code());

                    Some(result)
                }
                _ => {
                    return None;
                }
            }
        }
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if self.decipher.is_none() {
            if data.len() < 16 {
                return None;
            }

            let hmac1 = MacResult::new(&data[..16]);
            let hmac2 = hmac_md5(&self.password_iv, &data[16..]);

            if hmac1 == hmac2 {
                let offset = 16 + self.decipher_iv.len();
                self.decipher_iv.copy_from_slice(&data[16..offset]);
                self.decipher = Some(create_cipher(&self.key, &self.decipher_iv));

                process!(&mut self.decipher, &data[offset..])
            } else {
                None
            }
        } else {
            process!(&mut self.decipher, data)
        }
    }
}

#[cfg(test)]
mod test {
    use encrypt::Encryptor;
    use std::str;

    #[test]
    fn encrypt_and_decrypt_in_order() {
        let password = "foo";
        let messages = vec!["a", "hi", "foo", "hello", "world"];

        let mut encryptor = Encryptor::new(password);
        for msg in messages.iter() {
            let encrypted = encryptor.encrypt(msg.as_bytes());
            assert!(encrypted.is_some());
            let encrypted = encrypted.unwrap();

            let decrypted = encryptor.decrypt(&encrypted);
            assert!(decrypted.is_some());
            let decrypted = decrypted.unwrap();

            assert_eq!(msg.as_bytes()[..], decrypted[..]);
        }
    }

    #[test]
    fn encrypt_and_decrypt_without_order() {
        let password = "foo";
        let messages = vec!["a", "hi", "foo", "hello", "world"];

        let mut encryptor = Encryptor::new(password);
        let mut buf_msg = vec![];
        let mut buf_encrypted = vec![];

        macro_rules! assert_decrypt {
            () => (
                let decrypted = encryptor.decrypt(&buf_encrypted);
                assert!(decrypted.is_some());
                let decrypted = decrypted.unwrap();
                assert_eq!(buf_msg[..], decrypted[..]);
                buf_msg.clear();
                buf_encrypted.clear();
            );
        }

        for i in 0..messages.len() {
            let msg = messages[i].as_bytes();
            let encrypted = encryptor.encrypt(msg);
            assert!(encrypted.is_some());
            let encrypted = encrypted.unwrap();

            buf_msg.extend_from_slice(msg);
            buf_encrypted.extend_from_slice(&encrypted);

            if i % 2 == 0 {
                assert_decrypt!();
            }
        }
        assert_decrypt!();
    }
}
