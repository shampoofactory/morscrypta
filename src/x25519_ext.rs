use super::error::Result;
use super::global::*;
use super::x25519_pem;

use hmac::Hmac;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub trait GenPBKDF2 {
    fn gen_pbkdf2(password: &[u8], iteration_count: u32) -> Self;
}

impl GenPBKDF2 for StaticSecret {
    fn gen_pbkdf2(password: &[u8], iteration_count: u32) -> Self {
        let mut bs = [0u8; 32];
        pbkdf2::pbkdf2::<Hmac<Sha256>>(password, SALT_KDF, iteration_count, &mut bs);
        Self::from(bs)
    }
}

pub trait PemImport: Sized {
    fn pem_import<B: AsRef<[u8]>>(input: B) -> Result<Self>;
}

impl PemImport for StaticSecret {
    fn pem_import<B: AsRef<[u8]>>(input: B) -> Result<Self> {
        x25519_pem::import_prv(input).map(StaticSecret::from)
    }
}

impl PemImport for PublicKey {
    fn pem_import<B: AsRef<[u8]>>(input: B) -> Result<Self> {
        x25519_pem::import_pub(input).map(PublicKey::from)
    }
}

pub trait PemExport {
    fn pem_export(&self) -> String;
}

impl PemExport for StaticSecret {
    fn pem_export(&self) -> String {
        x25519_pem::export_prv(&self.to_bytes())
    }
}

impl PemExport for PublicKey {
    fn pem_export(&self) -> String {
        x25519_pem::export_pub(&self.as_bytes())
    }
}
