macro_rules! define_methods {
    [$($method:tt => ($key_len:expr, $iv_len:expr, $lib:tt),)*] => (
        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone, Copy, Hash, Eq, Ord, PartialEq, PartialOrd)]
        pub enum Method {
            $(
                $method,
            )*
        }

        impl Method {
            pub fn from(method: &str) -> Option<Method> {
                match method {
                    $(
                        stringify!($method) => Some(Method::$method),
                    )*
                    _ => None,
                }
            }

            pub fn info(self) -> (usize, usize) {
                match self {
                    $(
                        Method::$method => ($key_len, $iv_len),
                    )*
                }
            }

            pub fn lib(self) -> BelongLib {
                match self {
                    $(
                        Method::$method => BelongLib::$lib,
                    )*
                }
            }
        }
    )
}

#[cfg(not(feature = "openssl"))]
define_methods!(
    aes_256_ctr => (32, 16, Crypto),
);

#[cfg(feature = "openssl")]
define_methods!(
    aes_256_ctr => (32, 16, Crypto),

    aes_128_cfb => (16, 16, Openssl),
    aes_192_cfb => (24, 16, Openssl),
    aes_256_cfb => (32, 16, Openssl),
    aes_128_ofb => (16, 16, Openssl),
    aes_192_ofb => (24, 16, Openssl),
    aes_256_ofb => (32, 16, Openssl),
    aes_128_ctr => (16, 16, Openssl),
    aes_192_ctr => (24, 16, Openssl),
    aes_128_cfb8 => (16, 16, Openssl),
    aes_192_cfb8 => (24, 16, Openssl),
    aes_256_cfb8 => (32, 16, Openssl),
    aes_128_cfb1 => (16, 16, Openssl),
    aes_192_cfb1 => (24, 16, Openssl),
    aes_256_cfb1 => (32, 16, Openssl),
    bf_cfb => (16, 8, Openssl),
    camellia_128_cfb => (16, 16, Openssl),
    camellia_192_cfb => (24, 16, Openssl),
    camellia_256_cfb => (32, 16, Openssl),
    cast5_cfb => (16, 8, Openssl),
    des_cfb => (8, 8, Openssl),
    idea_cfb => (16, 8, Openssl),
    rc2_cfb => (16, 8, Openssl),
    rc4 => (16, 0, Openssl),
    seed_cfb => (16, 16, Openssl),
);

pub enum BelongLib {
    Crypto,
    Openssl,
}
