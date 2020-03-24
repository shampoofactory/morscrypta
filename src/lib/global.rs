use hkdf::Hkdf;
use hmac::Hmac;
use sha2::Sha256;

pub type HmacSha256 = Hmac<Sha256>;
pub type HkdfSha256 = Hkdf<Sha256>;

pub const INFO_KEY: &[u8] = b"KEY info default";
pub const INFO_MAC: &[u8] = b"MAC info default";
pub const SALT_KDF: &[u8] = b"KDF salt default";

pub const MAX_ENC_LEN: u64 = 1024 * 1024 * 1024;
