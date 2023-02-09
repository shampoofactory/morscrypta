use super::error::{Error, Result};
use super::global::*;

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes256;
use ctr::Ctr128BE;
use hkdf::Hkdf;
use hmac::digest::CtOutput;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use std::io::prelude::*;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct CryptorCore {
    cipher_key: [u8; 32],
    hmac_key: [u8; 64],
}

impl CryptorCore {
    #[inline(always)]
    pub fn with_ikm(ikm: &[u8]) -> Self {
        let mut cipher_key = [0u8; 32];
        let mut hmac_key = [0u8; 64];

        let h = Hkdf::<Sha256>::new(None, ikm);
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
        let len = 0;
        Encryptor { cipher, hmac, len }
    }

    #[inline(always)]
    pub fn decryptor(self) -> Decryptor {
        let cipher = self.cipher();
        let hmac = self.hmac();
        Decryptor { cipher, hmac }
    }

    #[inline(always)]
    fn cipher(&self) -> Ctr128BE<Aes256> {
        Ctr128BE::<Aes256>::new(&self.cipher_key.into(), &[0u8; 16].into())
    }

    #[inline(always)]
    fn hmac(&self) -> Hmac<Sha256> {
        Hmac::<Sha256>::new(self.hmac_key.as_slice().into())
    }
}

pub trait Cryptor {
    fn process(&mut self, buf: &mut [u8]) -> Result<()>;

    fn process_write<W>(&mut self, buf: &mut [u8], dst: &mut W) -> Result<()>
    where
        W: Write,
    {
        self.process(buf)?;
        dst.write_all(buf)?;
        Ok(())
    }

    fn finalize(self) -> CtOutput<Hmac<Sha256>>;
}

pub struct Encryptor {
    cipher: Ctr128BE<Aes256>,
    hmac: Hmac<Sha256>,
    len: u64,
}

impl Cryptor for Encryptor {
    fn process(&mut self, buf: &mut [u8]) -> Result<()> {
        self.len += buf.len() as u64;
        if self.len > MAX_ENC_LEN {
            return Err(Error::InputOverflow);
        }
        self.cipher.apply_keystream(buf);
        self.hmac.update(buf);
        Ok(())
    }

    fn finalize(self) -> CtOutput<Hmac<Sha256>> {
        self.hmac.finalize()
    }
}

pub struct Decryptor {
    cipher: Ctr128BE<Aes256>,
    hmac: Hmac<Sha256>,
}

impl Cryptor for Decryptor {
    fn process(&mut self, buf: &mut [u8]) -> Result<()> {
        self.hmac.update(buf);
        self.cipher.apply_keystream(buf);
        Ok(())
    }

    fn finalize(self) -> CtOutput<Hmac<Sha256>> {
        self.hmac.finalize()
    }
}
