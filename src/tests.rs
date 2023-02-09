use x25519_dalek::StaticSecret;

use crate::{GenPBKDF2, PemImport};

fn do_decrypt(prv_key: StaticSecret, ciphertext: &[u8], plaintext: &[u8]) -> crate::Result<()> {
    let mut decrypt = Vec::default();
    crate::decrypt(&mut &ciphertext[..], &mut decrypt, &prv_key)?;
    assert_eq!(decrypt, plaintext);
    Ok(())
}

#[test]
fn decrypt_pbkdf2() -> crate::Result<()> {
    let plaintext = include_bytes!("../data/data.bin");
    let ciphertext = include_bytes!("../data/enc1.bin");
    let prv_pem = include_bytes!("../data/prv.pem");
    let prv_key = StaticSecret::pem_import(prv_pem).unwrap();
    do_decrypt(prv_key, ciphertext, plaintext)
}

#[test]
fn decrypt_pem() -> crate::Result<()> {
    let plaintext = include_bytes!("../data/data.bin");
    let ciphertext = include_bytes!("../data/enc0.bin");
    let password = "LoremIpsumFlyingPossum500";
    let prv_key = StaticSecret::gen_pbkdf2(password.as_bytes(), 100000);
    do_decrypt(prv_key, ciphertext, plaintext)
}
