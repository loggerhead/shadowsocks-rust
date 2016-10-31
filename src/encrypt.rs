use rand::{Rng, OsRng};
use crypto::mac::Mac;
use crypto::md5::Md5;
use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::digest::Digest;
use crypto::aes::{ctr, KeySize};
use crypto::symmetriccipher::SynchronousStreamCipher;

use network::{NetworkReadBytes, NetworkWriteBytes};

const BUF_SIZE: usize = 64 * 1024;

type Cipher = Box<SynchronousStreamCipher + 'static>;

pub struct Encryptor {
    ota_helper: Option<OtaHelper>,
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
            ota_helper: None,
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

    #[cfg(feature = "sslocal")]
    pub fn enable_ota(&mut self, addr_type: u8, header_length: usize, data: &[u8]) -> Option<Vec<u8>> {
        let mut ota = OtaHelper::new();
        // OTA header
        let mut header = Vec::with_capacity(header_length + 10);
        header.push(addr_type);
        header.extend_from_slice(&data[1..header_length]);

        // sha1 of header
        let mut key = Vec::with_capacity(self.cipher_iv.len() + self.key.len());
        key.extend_from_slice(&self.cipher_iv);
        key.extend_from_slice(&self.key);
        let sha1 = ota.hmac_sha1(&header, &key);
        header.extend_from_slice(&sha1);

        let data = &data[header_length..];
        // TODO: refactor after change `pack_chunk` to return `result`
        if data.is_empty() {
            self.ota_helper = Some(ota);
            Some(header)
        } else {
            // OTA chunk
            let chunk = try_opt!(ota.pack_chunk(data, &self.cipher_iv));

            // OTA request
            let mut data = Vec::with_capacity(header.len() + chunk.len());
            data.extend_from_slice(&header);
            data.extend_from_slice(&chunk);

            self.ota_helper = Some(ota);
            Some(data)
        }
    }

    #[cfg(not(feature = "sslocal"))]
    pub fn enable_ota(&mut self, _addr_type: u8, header_length: usize, data: &[u8]) -> Option<Vec<u8>> {
        let mut ota = OtaHelper::new();
        // verify OTA header
        let header = &data[..header_length];
        let sha1 = &data[header_length..header_length + 10];
        let mut key = Vec::with_capacity(self.decipher_iv.len() + self.key.len());
        key.extend_from_slice(&self.decipher_iv);
        key.extend_from_slice(&self.key);
        if !ota.verify_sha1(header, &key, sha1) {
            return None;
        }

        // unpack OTA chunks
        let res = ota.unpack_chunk(&data[header_length + 10..], &self.decipher_iv);
        self.ota_helper = Some(ota);
        res
    }

    fn raw_encrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if let Some(ref mut cipher) = self.cipher {
            let mut output = vec![0u8; data.len()];
            cipher.process(data, output.as_mut_slice());
            Some(output)
        } else {
            None
        }
    }

    fn raw_decrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if let Some(ref mut cipher) = self.decipher {
            let mut output = vec![0u8; data.len()];
            cipher.process(data, output.as_mut_slice());
            Some(output)
        } else {
            None
        }
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        // if first request
        if !self.is_iv_sent {
            self.is_iv_sent = true;
            match self.raw_encrypt(data) {
                Some(ref mut encrypted) => {
                    let len = self.cipher_iv.len() + encrypted.len();
                    let mut result = Vec::with_capacity(len);
                    result.extend_from_slice(&self.cipher_iv);
                    result.append(encrypted);

                    Some(result)
                }
                _ => None,
            }
        } else {
            // if this is a OTA request
            if cfg!(feature = "sslocal") && self.ota_helper.is_some() {
                let mut ota = self.ota_helper.take().unwrap();
                let data = &try_opt!(ota.pack_chunk(data, &self.cipher_iv));
                self.ota_helper = Some(ota);
                self.raw_encrypt(data)
            } else {
                self.raw_encrypt(data)
            }
        }
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        // if first request
        if self.decipher.is_none() {
            if data.len() < 16 {
                None
            } else {
                let iv_len = self.decipher_iv.len();
                self.decipher_iv[..].copy_from_slice(&data[..iv_len]);
                self.decipher = Some(create_cipher(&self.key, &self.decipher_iv));
                self.raw_decrypt(&data[iv_len..])
            }
        } else {
            let mut decrypted = try_opt!(self.raw_decrypt(data));
            // if this is a OTA request
            if !cfg!(feature = "sslocal") && self.ota_helper.is_some() {
                let mut ota = self.ota_helper.take().unwrap();
                decrypted = try_opt!(ota.unpack_chunk(&decrypted, &self.decipher_iv));
                self.ota_helper = Some(ota);
            }
            Some(decrypted)
        }
    }

    fn raw_encrypt_udp(&self, key: &[u8], iv: &[u8], data: &[u8]) -> (Cipher, Vec<u8>) {
        let mut cipher = create_cipher(key, iv);
        let mut encrypted = vec![0u8; data.len()];
        cipher.process(data, encrypted.as_mut_slice());

        let mut res = Vec::with_capacity(iv.len() + data.len());
        res.extend_from_slice(iv);
        res.extend_from_slice(&encrypted);

        (cipher, res)
    }

    fn raw_decrypt_udp(&self, iv_len: usize, key: &[u8], data: &[u8]) -> (Vec<u8>, Cipher, Vec<u8>) {
        let iv = data[..iv_len].to_vec();

        let mut decipher = create_cipher(key, &iv);
        let mut decrypted = vec![0u8; data.len() - iv_len];
        decipher.process(&data[iv_len..], decrypted.as_mut_slice());

        (iv, decipher, decrypted)
    }

    pub fn encrypt_udp(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let (key, iv) = gen_key_iv(&self.password);
        let (cipher, data) = self.raw_encrypt_udp(&key, &iv, data);
        self.key = key;
        self.cipher_iv = iv;
        self.cipher = Some(cipher);
        Some(data)
    }

    pub fn decrypt_udp(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let (key, _iv) = gen_key_iv(&self.password);
        let (iv, decipher, data) = self.raw_decrypt_udp(_iv.len(), &key, data);
        self.key = key;
        self.decipher_iv = iv;
        self.decipher = Some(decipher);
        Some(data)
    }

    pub fn encrypt_udp_ota(&mut self, addr_type: u8, data: &[u8]) -> Option<Vec<u8>> {
        if self.ota_helper.is_none() {
            self.ota_helper = Some(OtaHelper::new());
        }
        let ota = self.ota_helper.take().unwrap();

        let mut chunk = Vec::with_capacity(data.len() + 10);
        chunk.push(addr_type);
        chunk.extend_from_slice(&data[1..]);

        let (key, iv) = gen_key_iv(&self.password);
        let mut ota_key = Vec::with_capacity(key.len() + iv.len());
        ota_key.extend_from_slice(&iv);
        ota_key.extend_from_slice(&key);

        let sha1 = ota.hmac_sha1(&chunk, &ota_key);
        chunk.extend_from_slice(&sha1);

        self.ota_helper = Some(ota);
        let (_, data) = self.raw_encrypt_udp(&key, &iv, &chunk);
        Some(data)
    }

    pub fn decrypt_udp_ota(&mut self, _addr_type: u8, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 10 {
            return None;
        }

        if self.ota_helper.is_none() {
            self.ota_helper = Some(OtaHelper::new());
        }
        let ota = self.ota_helper.take().unwrap();

        let mut ota_key = Vec::with_capacity(self.key.len() + self.decipher_iv.len());
        ota_key.extend_from_slice(&self.decipher_iv);
        ota_key.extend_from_slice(&self.key);

        let sha1 = &data[data.len()-10..];
        let data = &data[..data.len()-10];

        if ota.verify_sha1(data, &ota_key, sha1) {
            self.ota_helper = Some(ota);
            Some(data.to_vec())
        } else {
            None
        }
    }
}

struct OtaHelper {
    index: i32,
    chunk_sha1: Vec<u8>,
    chunk_len: u16,
    chunk_buf: Vec<u8>,
}

impl OtaHelper {
    fn new() -> OtaHelper {
        OtaHelper {
            index: 0,
            chunk_sha1: Vec::with_capacity(10),
            chunk_len: 0,
            chunk_buf: Vec::with_capacity(BUF_SIZE),
        }
    }

    fn hmac_sha1(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut hmac = Hmac::new(Sha1::new(), key);
        let len = hmac.output_bytes();
        let mut res = Vec::with_capacity(len);
        unsafe { res.set_len(len); }
        hmac.input(data);
        hmac.raw_result(&mut res);
        unsafe { res.set_len(10); }
        res
    }

    fn verify_sha1(&self, data: &[u8], key: &[u8], sha1: &[u8]) -> bool {
        sha1.eq(&self.hmac_sha1(data, key)[..])
    }

    fn pack_chunk(&mut self, data: &[u8], cipher_iv: &[u8]) -> Option<Vec<u8>> {
        let mut ota_key = Vec::with_capacity(cipher_iv.len() + 4);
        ota_key.extend_from_slice(cipher_iv);
        try_opt!(ota_key.put_i32(self.index));

        let sha1 = self.hmac_sha1(data, &ota_key);
        let mut chunk = Vec::with_capacity(12 + data.len());
        try_opt!(chunk.put_u16(data.len() as u16));
        chunk.extend_from_slice(&sha1);
        chunk.extend_from_slice(data);

        self.index += 1;
        Some(chunk)
    }

    // TODO: change to return `Result`
    fn unpack_chunk(&mut self, mut data: &[u8], decipher_iv: &[u8]) -> Option<Vec<u8>> {
        let mut unpacked = Vec::with_capacity(data.len());

        while !data.is_empty() {
            // make sure read a complete header
            if self.chunk_len == 0 {
                // wait a complete header
                if data.len() + self.chunk_buf.len() < 12 {
                    self.chunk_buf.extend_from_slice(&data);
                    break;
                } else {
                    // split DATA.LEN, HMAC-SHA1 from DATA
                    let offset = 12 - self.chunk_buf.len();
                    self.chunk_buf.extend_from_slice(&data[..offset]);
                    self.chunk_len = try_opt!((&self.chunk_buf[..2]).get_u16());
                    unsafe { self.chunk_sha1.set_len(0); }
                    self.chunk_sha1.extend_from_slice(&self.chunk_buf[2..]);
                    unsafe { self.chunk_buf.set_len(0); }
                    data = &data[offset..];
                }
            }

            if data.len() + self.chunk_buf.len() < self.chunk_len as usize {
                self.chunk_buf.extend_from_slice(data);
                break;
            // if there are one or more chunks
            } else {
                let offset = self.chunk_len as usize - self.chunk_buf.len();
                // make sure there is a chunk data in chunk_buf
                self.chunk_buf.extend_from_slice(&data[..offset]);
                data = &data[offset..];

                let mut key = Vec::with_capacity(decipher_iv.len() + 4);
                key.extend_from_slice(decipher_iv);
                try_opt!(key.put_i32(self.index));
                self.index += 1;

                if self.verify_sha1(&self.chunk_buf, &key, &self.chunk_sha1) {
                    unpacked.extend_from_slice(&self.chunk_buf);
                    self.chunk_len = 0;
                    unsafe { self.chunk_buf.set_len(0); }
                } else {
                    self.chunk_len = 0;
                    unsafe { self.chunk_buf.set_len(0); }
                    break;
                }
            }
        }

        Some(unpacked)
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
