use std::sync::Arc;
use std::sync::Mutex;
use lru_time_cache::LruCache;

use rand::{Rng, OsRng};
use rust_crypto::util::fixed_time_eq;
use rust_crypto::mac::Mac;
use rust_crypto::md5::Md5;
use rust_crypto::sha1::Sha1;
use rust_crypto::hmac::Hmac;
use rust_crypto::digest::Digest;
use network::{NetworkReadBytes, NetworkWriteBytes};

use super::error::CipherResult;
use super::{Method, Cipher, Mode};
use super::cipher::StreamCipher;

const BUF_SIZE: usize = 64 * 1024;
const KEY_CACHE_SIZE: usize = 1024;
const HMAC_SHA1_LEN: usize = 10;

pub struct Encryptor {
    ota_helper: Option<OtaHelper>,
    is_iv_sent: bool,
    key: Arc<Vec<u8>>,
    iv_len: usize,
    password: String,
    method: Method,
    cipher: Cipher,
    decipher: Option<Cipher>,
}

// First packet format:
//
// +-----------+----------------+
// | cipher iv | encrypted data |
// +-----------+----------------+
impl Encryptor {
    pub fn new(password: &str, method: Method) -> CipherResult<Encryptor> {
        let (key, iv) = gen_key_iv(password, method);
        let iv_len = iv.len();
        let cipher = Cipher::new(method, Mode::Encrypt, key.clone(), iv)?;

        Ok(Encryptor {
            ota_helper: None,
            is_iv_sent: false,
            key: key,
            iv_len: iv_len,
            password: String::from(password),
            method: method,
            cipher: cipher,
            decipher: None,
        })
    }

    #[cfg(feature = "sslocal")]
    fn cipher_iv(&self) -> &[u8] {
        self.cipher.iv()
    }

    fn decipher_iv(&self) -> Option<&[u8]> {
        self.decipher.as_ref().map(|c| c.iv())
    }

    #[cfg(feature = "sslocal")]
    pub fn enable_ota(&mut self,
                      addr_type: u8,
                      header_length: usize,
                      data: &[u8])
                      -> Option<Vec<u8>> {
        let mut ota = OtaHelper::new();
        // OTA header
        let mut header = vec![];
        header.push(addr_type);
        // first byte is addr_type
        header.extend_from_slice(&data[1..header_length]);

        // sha1 of header
        let mut key = vec![];
        key.extend_from_slice(self.cipher_iv());
        key.extend_from_slice(&self.key);
        let sha1 = ota.hmac_sha1(&header, &key);
        header.extend_from_slice(&sha1);

        let data = &data[header_length..];
        if data.is_empty() {
            self.ota_helper = Some(ota);
            Some(header)
        } else {
            // OTA chunk
            let chunk = try_opt!(ota.pack_chunk(data, &self.cipher_iv()));

            // OTA request
            let mut data = vec![];
            data.extend_from_slice(&header);
            data.extend_from_slice(&chunk);

            self.ota_helper = Some(ota);
            Some(data)
        }
    }

    #[cfg(not(feature = "sslocal"))]
    pub fn enable_ota(&mut self,
                      _addr_type: u8,
                      header_length: usize,
                      data: &[u8])
                      -> Option<Vec<u8>> {
        let mut ota = OtaHelper::new();
        // verify OTA header
        let header = &data[..header_length];
        let sha1 = &data[header_length..header_length + HMAC_SHA1_LEN];
        let mut key = vec![];
        key.extend_from_slice(try_opt!(self.decipher_iv()));
        key.extend_from_slice(&self.key);
        if !ota.verify_sha1(header, &key, sha1) {
            return None;
        }

        // unpack OTA chunks
        let res = ota.unpack_chunk(&data[header_length + HMAC_SHA1_LEN..],
                                   try_opt!(self.decipher_iv()));
        self.ota_helper = Some(ota);
        res
    }

    #[cfg(feature = "disable-encrypt")]
    pub fn raw_encrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        Some(data.to_vec())
    }

    #[cfg(feature = "disable-encrypt")]
    pub fn raw_decrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        Some(data.to_vec())
    }

    #[cfg(not(feature = "disable-encrypt"))]
    pub fn raw_encrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let mut output = vec![];
        self.cipher.update(data, &mut output).ok().map(|_| output)
    }

    #[cfg(not(feature = "disable-encrypt"))]
    pub fn raw_decrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        self.decipher.as_mut().and_then(|decipher| {
            let mut output = vec![];
            decipher.update(data, &mut output).ok().map(|_| output)
        })
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        // if first request
        if !self.is_iv_sent {
            self.is_iv_sent = true;
            match self.raw_encrypt(data) {
                Some(ref mut encrypted) => {
                    let mut result = vec![];
                    result.extend_from_slice(self.cipher.iv());
                    result.append(encrypted);

                    Some(result)
                }
                _ => None,
            }
        } else {
            // if this is a OTA request
            if cfg!(feature = "sslocal") && self.ota_helper.is_some() {
                let mut ota = self.ota_helper.take().unwrap();
                let data = &try_opt!(ota.pack_chunk(data, &self.cipher.iv()));
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
            let iv_len = self.iv_len;
            if data.len() > iv_len {
                let iv = Vec::from(&data[..iv_len]);
                self.decipher = Cipher::new(self.method, Mode::Decrypt, self.key.clone(), iv).ok();
                self.raw_decrypt(&data[iv_len..])
            } else {
                None
            }
        } else {
            let mut decrypted = try_opt!(self.raw_decrypt(data));
            // if this is a OTA request
            if !cfg!(feature = "sslocal") && self.ota_helper.is_some() {
                let mut ota = self.ota_helper.take().unwrap();
                decrypted = try_opt!(ota.unpack_chunk(&decrypted, try_opt!(self.decipher_iv())));
                self.ota_helper = Some(ota);
            }
            Some(decrypted)
        }
    }

    fn raw_encrypt_udp(&self, key: Arc<Vec<u8>>, iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        let mut cipher = try_opt!(Cipher::new(self.method, Mode::Encrypt, key, Vec::from(iv)).ok());
        let mut encrypted = vec![0u8; data.len()];
        try_opt!(cipher.update(data, &mut encrypted).ok());

        let mut res = vec![];
        res.extend_from_slice(iv);
        res.extend_from_slice(&encrypted);
        Some(res)
    }

    fn raw_decrypt_udp(&self,
                       iv_len: usize,
                       key: Arc<Vec<u8>>,
                       data: &[u8])
                       -> Option<(Cipher, Vec<u8>)> {
        let iv = &data[..iv_len];
        let mut decipher = try_opt!(Cipher::new(self.method, Mode::Decrypt, key, Vec::from(iv))
            .ok());
        let mut decrypted = vec![0u8; data.len() - iv_len];
        try_opt!(decipher.update(&data[iv_len..], &mut decrypted).ok());

        Some((decipher, decrypted))
    }

    pub fn encrypt_udp(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let (key, iv) = gen_key_iv(&self.password, self.method);
        self.raw_encrypt_udp(key, &iv, data)
    }

    pub fn decrypt_udp(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let (key, _iv) = gen_key_iv(&self.password, self.method);
        self.raw_decrypt_udp(_iv.len(), key, data).and_then(|(decipher, data)| {
            self.decipher = Some(decipher);
            Some(data)
        })
    }

    pub fn encrypt_udp_ota(&mut self, addr_type: u8, data: &[u8]) -> Option<Vec<u8>> {
        if self.ota_helper.is_none() {
            self.ota_helper = Some(OtaHelper::new());
        }
        let ota = self.ota_helper.take().unwrap();

        let mut chunk = Vec::with_capacity(data.len() + HMAC_SHA1_LEN);
        chunk.push(addr_type);
        chunk.extend_from_slice(&data[1..]);

        let (key, iv) = gen_key_iv(&self.password, self.method);
        let mut ota_key = Vec::with_capacity(key.len() + iv.len());
        ota_key.extend_from_slice(&iv);
        ota_key.extend_from_slice(&key);

        let sha1 = ota.hmac_sha1(&chunk, &ota_key);
        chunk.extend_from_slice(&sha1);

        self.ota_helper = Some(ota);
        self.raw_encrypt_udp(key, &iv, &chunk)
    }

    pub fn decrypt_udp_ota(&mut self, _addr_type: u8, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < HMAC_SHA1_LEN {
            return None;
        }

        if self.ota_helper.is_none() {
            self.ota_helper = Some(OtaHelper::new());
        }
        let ota = self.ota_helper.take().unwrap();

        let mut ota_key = vec![];
        ota_key.extend_from_slice(try_opt!(self.decipher_iv()));
        ota_key.extend_from_slice(&self.key);

        let sha1 = &data[data.len() - HMAC_SHA1_LEN..];
        let data = &data[..data.len() - HMAC_SHA1_LEN];

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
            chunk_sha1: Vec::with_capacity(HMAC_SHA1_LEN),
            chunk_len: 0,
            chunk_buf: Vec::with_capacity(BUF_SIZE),
        }
    }

    fn hmac_sha1(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut hmac = Hmac::new(Sha1::new(), key);
        let len = hmac.output_bytes();
        let mut res = vec![0u8; len];
        hmac.input(data);
        hmac.raw_result(&mut res);
        res.resize(HMAC_SHA1_LEN, 0);
        res
    }

    fn verify_sha1(&self, data: &[u8], key: &[u8], sha1: &[u8]) -> bool {
        fixed_time_eq(sha1, &self.hmac_sha1(data, key)[..])
    }

    fn pack_chunk(&mut self, data: &[u8], cipher_iv: &[u8]) -> Option<Vec<u8>> {
        let mut ota_key = vec![];
        ota_key.extend_from_slice(cipher_iv);
        pack!(i32, ota_key, self.index);

        let sha1 = self.hmac_sha1(data, &ota_key);
        let mut chunk = vec![];
        pack!(u16, chunk, data.len() as u16);
        chunk.extend_from_slice(&sha1);
        chunk.extend_from_slice(data);

        self.index += 1;
        Some(chunk)
    }

    fn unpack_chunk(&mut self, mut data: &[u8], decipher_iv: &[u8]) -> Option<Vec<u8>> {
        let mut unpacked = Vec::with_capacity(data.len());

        while !data.is_empty() {
            // make sure read a complete header
            if self.chunk_len == 0 {
                // wait a complete header
                if data.len() + self.chunk_buf.len() < 12 {
                    self.chunk_buf.extend_from_slice(data);
                    break;
                } else {
                    // split DATA.LEN, HMAC-SHA1 from DATA
                    let offset = 12 - self.chunk_buf.len();
                    self.chunk_buf.extend_from_slice(&data[..offset]);
                    self.chunk_len = unpack!(u16, &self.chunk_buf[..2]);
                    unsafe {
                        self.chunk_sha1.set_len(0);
                    }
                    self.chunk_sha1.extend_from_slice(&self.chunk_buf[2..]);
                    unsafe {
                        self.chunk_buf.set_len(0);
                    }
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
                pack!(i32, key, self.index);
                self.index += 1;

                if self.verify_sha1(&self.chunk_buf, &key, &self.chunk_sha1) {
                    unpacked.extend_from_slice(&self.chunk_buf);
                    self.chunk_len = 0;
                    unsafe {
                        self.chunk_buf.set_len(0);
                    }
                } else {
                    self.chunk_len = 0;
                    unsafe {
                        self.chunk_buf.set_len(0);
                    }
                    break;
                }
            }
        }

        Some(unpacked)
    }
}

fn gen_key_iv(password: &str, method: Method) -> (Arc<Vec<u8>>, Vec<u8>) {
    lazy_static! {
        static ref CACHE: Mutex<LruCache<(String, Method), Arc<Vec<u8>>>> =
            Mutex::new(LruCache::with_capacity(KEY_CACHE_SIZE));
    }

    let (key_len, iv_len) = Method::info(method);

    let key = match CACHE.lock().unwrap().get(&(password.to_string(), method)) {
        Some(key) => key.clone(),
        None => Arc::new(evp_bytes_to_key(password, key_len, iv_len).0),
    };

    let mut iv = vec![0u8; iv_len];
    let _ = OsRng::new().map(|mut rng| rng.fill_bytes(&mut iv));
    (key, iv)
}

// equivalent to OpenSSL's EVP_BytesToKey() with count 1
fn evp_bytes_to_key(password: &str, key_len: usize, iv_len: usize) -> (Vec<u8>, Vec<u8>) {
    const MD5_LEN: usize = 16;
    let mut i = 0;
    let mut m: Vec<Box<[u8; MD5_LEN]>> = Vec::with_capacity(key_len + iv_len);
    let password = password.as_bytes();
    let mut data = Vec::with_capacity(MD5_LEN + password.len());
    let mut cnt = 0;

    while cnt < key_len + iv_len {
        unsafe {
            data.set_len(0);
        }
        if i > 0 {
            data.extend_from_slice(&*m[i - 1]);
        }
        data.extend_from_slice(password);

        let mut buf = Box::new([0u8; MD5_LEN]);
        let mut md5 = Md5::new();
        md5.input(&data);
        md5.result(&mut *buf);
        cnt += buf.len();

        m.push(buf);
        i += 1;
    }

    let mut tmp: Vec<u8> = Vec::with_capacity(MD5_LEN * m.capacity());
    for bytes in m {
        tmp.extend_from_slice(&*bytes);
    }

    let key = Vec::from(&tmp[..key_len]);
    let iv = Vec::from(&tmp[key_len..key_len + iv_len]);

    (key, iv)
}
