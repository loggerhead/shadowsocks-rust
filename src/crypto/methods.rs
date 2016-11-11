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
    aes_128_ctr => (16, 16, Crypto),
    aes_192_ctr => (24, 16, Crypto),
    aes_256_ctr => (32, 16, Crypto),
    rc4 => (16, 0, Crypto),
    hc128 => (16, 16, Crypto),
    salsa20 => (32, 8, Crypto),
    xsalsa20 => (32, 24, Crypto),
    chacha20 => (32, 8, Crypto),
    xchacha20 => (32, 24, Crypto),
    sosemanuk => (32, 16, Crypto),
);

#[cfg(feature = "openssl")]
define_methods!(
    aes_128_ctr => (16, 16, Crypto),
    aes_192_ctr => (24, 16, Crypto),
    aes_256_ctr => (32, 16, Crypto),
    rc4 => (16, 0, Crypto),
    hc128 => (16, 16, Crypto),
    salsa20 => (32, 8, Crypto),
    xsalsa20 => (32, 24, Crypto),
    chacha20 => (32, 8, Crypto),
    xchacha20 => (32, 24, Crypto),
    sosemanuk => (32, 16, Crypto),

    aes_128_cfb => (16, 16, Openssl),
    aes_256_cfb => (32, 16, Openssl),
    aes_128_cfb1 => (16, 16, Openssl),
    aes_256_cfb1 => (32, 16, Openssl),
    aes_128_cfb8 => (16, 16, Openssl),
    aes_256_cfb8 => (32, 16, Openssl),
);

pub enum BelongLib {
    Crypto,
    #[cfg(feature = "openssl")]
    Openssl,
}
