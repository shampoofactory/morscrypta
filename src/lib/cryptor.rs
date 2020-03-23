use super::global::*;

use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes256Ctr;
use hmac::crypto_mac::MacResult;
use hmac::Mac;

use std::io;
use std::io::prelude::*;

pub struct CryptorCore {
    cipher_key: [u8; 32],
    hmac_key: [u8; 64],
}

impl CryptorCore {
    #[inline(always)]
    pub fn with_ikm(ikm: &[u8]) -> Self {
        let mut cipher_key = [0u8; 32];
        let mut hmac_key = [0u8; 64];

        let h = HkdfSha256::new(None, ikm);
        h.expand(INFO_KEY, &mut cipher_key).unwrap();
        h.expand(INFO_MAC, &mut hmac_key).unwrap();

        Self {
            cipher_key,
            hmac_key,
        }
    }

    #[inline(always)]
    pub fn encryptor(self) -> Encryptor {
        let cipher = self.cipher();
        let hmac = self.hmac();
        Encryptor { cipher, hmac }
    }

    #[inline(always)]
    pub fn decryptor(self) -> Decryptor {
        let cipher = self.cipher();
        let hmac = self.hmac();
        Decryptor { cipher, hmac }
    }

    #[inline(always)]
    fn cipher(&self) -> Aes256Ctr {
        let cipher_key = GenericArray::from_slice(&self.cipher_key);
        let cipher_nonce = GenericArray::from_slice(&[0u8; 16]);
        Aes256Ctr::new(&cipher_key, &cipher_nonce)
    }

    #[inline(always)]
    fn hmac(&self) -> HmacSha256 {
        let hmac_key = GenericArray::from_slice(&self.hmac_key);
        HmacSha256::new(hmac_key)
    }
}

pub trait Cryptor {
    fn process(&mut self, buf: &mut [u8]);

    fn process_write<W>(&mut self, buf: &mut [u8], dst: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        self.process(buf);
        dst.write_all(buf)
    }

    fn finalize(self) -> MacResult<<HmacSha256 as Mac>::OutputSize>;
}

pub struct Encryptor {
    cipher: Aes256Ctr,
    hmac: HmacSha256,
}

impl Cryptor for Encryptor {
    fn process(&mut self, buf: &mut [u8]) {
        self.cipher.apply_keystream(buf);
        self.hmac.input(buf);
    }

    fn finalize(self) -> MacResult<<HmacSha256 as Mac>::OutputSize> {
        self.hmac.result()
    }
}

pub struct Decryptor {
    cipher: Aes256Ctr,
    hmac: HmacSha256,
}

impl Cryptor for Decryptor {
    fn process(&mut self, buf: &mut [u8]) {
        self.hmac.input(buf);
        self.cipher.apply_keystream(buf);
    }

    fn finalize(self) -> MacResult<<HmacSha256 as Mac>::OutputSize> {
        self.hmac.result()
    }
}
