use super::error::{Error, Result};
use super::x25519_der;

use pem::Pem;

const PRIVATE_KEY_TAG: &str = "PRIVATE KEY";
const PUBLIC_KEY_TAG: &str = "PUBLIC KEY";

pub fn import_pub<B: AsRef<[u8]>>(input: B) -> Result<[u8; 32]> {
    let pem = pem::parse(input).map_err(|u| Error::KeyImport(u.to_string()))?;
    if pem.tag == PUBLIC_KEY_TAG {
        x25519_der::import_pub(&pem.contents)
    } else {
        Err(Error::KeyImport(format!(
            "invalid public key tag: {}",
            pem.tag
        )))
    }
}

pub fn export_pub(bs: &[u8; 32]) -> String {
    let tag = PUBLIC_KEY_TAG.to_owned();
    let contents = x25519_der::export_pub(bs);
    let pem = Pem { contents, tag };
    pem::encode(&pem)
}

pub fn import_prv<B: AsRef<[u8]>>(input: B) -> Result<[u8; 32]> {
    let pem = pem::parse(input).map_err(|u| Error::KeyImport(u.to_string()))?;
    if pem.tag == PRIVATE_KEY_TAG {
        x25519_der::import_prv(&pem.contents)
    } else {
        Err(Error::KeyImport(format!(
            "invalid private key tag: {}",
            pem.tag
        )))
    }
}

pub fn export_prv(bs: &[u8; 32]) -> String {
    let tag = PRIVATE_KEY_TAG.to_owned();
    let contents = x25519_der::export_prv(bs);
    let pem = Pem { contents, tag };
    pem::encode(&pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    const PEM_PUB_KEY: &str = "-----BEGIN PUBLIC KEY-----\r\n\
                               MCowBQYDK2VuAyEAiE/A6WP+LYU5VttZTh/qeKEgThj+ws/4fQQJZJ2EwWI=\r\n\
                               -----END PUBLIC KEY-----\r\n";

    const RAW_PUB_KEY: [u8; 32] =
        hex!("884FC0E963FE2D853956DB594E1FEA78A1204E18FEC2CFF87D0409649D84C162");

    const PEM_PRV_KEY: &str = "-----BEGIN PRIVATE KEY-----\r\n\
                               MC4CAQAwBQYDK2VuBCIEIBhZWXwlKdnRCFvrLb5N+4ogkBZQ5aG5xDQkZAXE7hxO\r\n\
                               -----END PRIVATE KEY-----\r\n";

    const RAW_PRV_KEY: [u8; 32] =
        hex!("1859597C2529D9D1085BEB2DBE4DFB8A20901650E5A1B9C434246405C4EE1C4E");

    #[test]
    fn test_import_pub() {
        let key = import_pub(PEM_PUB_KEY.as_bytes()).unwrap();
        assert_eq!(key, RAW_PUB_KEY);
    }

    #[test]
    fn test_export_pub() {
        let pem = export_pub(&RAW_PUB_KEY);
        assert_eq!(PEM_PUB_KEY, pem);
    }
    #[test]

    fn test_import_prv() {
        let key = import_prv(PEM_PRV_KEY.as_bytes()).unwrap();
        assert_eq!(key, RAW_PRV_KEY);
    }

    #[test]
    fn test_export_prv() {
        let pem = export_prv(&RAW_PRV_KEY);
        assert_eq!(PEM_PRV_KEY, pem);
    }
}
