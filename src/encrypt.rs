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


pub struct Encryptor {
    is_first_packet: bool,
    is_local: bool,
    key: Vec<u8>,
    password_iv: Vec<u8>,
    cipher_iv: Vec<u8>,
    cipher: Option<Cipher>,
}

// First packet format:
//
// +----------------+-----------+------+
// | encrypted data | cipher iv | hmac |
// +----------------+-----------+------+
//                      16         16
impl Encryptor {
    pub fn new(password: &str, is_local: bool) -> Encryptor {
        let (key, password_iv) = gen_key_iv(password, 256, 32);

        let mut this = Encryptor {
            is_first_packet: true,
            is_local: is_local,
            key: key,
            password_iv: password_iv,
            cipher_iv: vec![0u8; 16],
            cipher: None,
        };

        if is_local {
            OsRng::new().unwrap().fill_bytes(&mut this.cipher_iv);
            this.cipher = Some(create_cipher(&this.key, &this.cipher_iv));
        }

        this
    }

    pub fn update(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if self.is_first_packet {
            self.is_first_packet = false;
            if self.is_local {
                return self.encrypt_first_packet(data);
            } else {
                return self.decrypt_first_packet(data);
            }
        } else {
            self.process(data)
        }
    }

    fn process(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let mut output = vec![0u8; data.len()];
        match self.cipher {
            Some(ref mut cipher) => cipher.process(data, output.as_mut_slice()),
            None => return None,
        }

        Some(output)
    }

    fn encrypt_first_packet(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let mut encrypted = self.process(data);
        match encrypted {
            Some(ref mut encrypted) => {
                encrypted.extend_from_slice(&self.cipher_iv);
                let hmac = hmac_md5(&self.password_iv, &encrypted);
                encrypted.extend_from_slice(hmac.code());
            }
            None => {}
        }

        encrypted
    }

    fn decrypt_first_packet(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 16 {
            return None;
        }

        let offset = data.len() - 16;
        let hmac1 = MacResult::new(&data[offset..]);
        let data = &data[..offset];
        let hmac2 = hmac_md5(&self.password_iv, data);

        if hmac1 == hmac2 {
            let offset = data.len() - self.cipher_iv.len();
            self.cipher_iv.copy_from_slice(&data[offset..]);
            self.cipher = Some(create_cipher(&self.key, &self.cipher_iv));

            self.process(&data[..offset])
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use encrypt::Encryptor;

    use std::str;

    #[test]
    fn test() {
        let messages = vec!["hi", "foo", "hello", "world"];

        let password = "foo";
        let mut encryptor = Encryptor::new(password, true);
        let mut decryptor = Encryptor::new(password, false);

        for msg in messages {
            let encrypted = encryptor.update(msg.as_bytes());
            assert!(encrypted.is_some());
            let encrypted = encrypted.unwrap();

            let decrypted = decryptor.update(&encrypted);
            assert!(decrypted.is_some());
            let decrypted = decrypted.unwrap();

            assert_eq!(msg.as_bytes()[..], decrypted[..]);
        }
    }
}
