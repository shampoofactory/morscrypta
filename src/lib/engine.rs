use super::cryptor::{Cryptor, CryptorCore};
use super::error::{Error, Result};
use super::read_ext::ReadFully;

use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use std::io::prelude::*;

const BLK_LEN: usize = 0x0000_8000;

#[inline(always)]
pub fn encrypt<R, W>(src: &mut R, dst: &mut W, pub_key: &PublicKey) -> Result<()>
where
    R: Read,
    W: Write,
{
    encrypt_internal(src, dst, pub_key, &mut [0u8; BLK_LEN + 64])
}

#[inline(always)]
fn encrypt_internal<R, W>(
    src: &mut R,
    dst: &mut W,
    pub_key: &PublicKey,
    buf: &mut [u8],
) -> Result<()>
where
    R: Read,
    W: Write,
{
    assert!(buf.len() >= 64 + 64);
    let blk_len = buf.len() - 64;

    let prv_ephemeral = StaticSecret::new(&mut OsRng);
    let pub_ephemeral = PublicKey::from(&prv_ephemeral);
    let ikm = prv_ephemeral.diffie_hellman(pub_key);

    let mut encryptor = CryptorCore::with_ikm(ikm.as_bytes()).encryptor();

    (&mut buf[0..32]).copy_from_slice(pub_ephemeral.as_bytes());
    loop {
        let n = src.read_fully(&mut buf[32..blk_len + 32])?;
        if n == blk_len {
            encryptor.process(&mut buf[32..blk_len + 32])?;
            dst.write_all(&buf[..blk_len])?;
            buf.copy_within(blk_len..blk_len + 32, 0);
        } else {
            encryptor.process(&mut buf[32..n + 32])?;
            let code = encryptor.finalize().code();
            (&mut buf[n + 32..n + 64]).copy_from_slice(&code);
            dst.write_all(&buf[..n + 64])?;
            break;
        }
    }
    Ok(())
}

#[inline(always)]
pub fn decrypt<R, W>(src: &mut R, dst: &mut W, prv_key: &StaticSecret) -> Result<()>
where
    R: Read,
    W: Write,
{
    decrypt_internal(src, dst, prv_key, &mut [0u8; BLK_LEN + 64])
}

#[inline(always)]
fn decrypt_internal<R, W>(
    src: &mut R,
    dst: &mut W,
    prv_key: &StaticSecret,
    buf: &mut [u8],
) -> Result<()>
where
    R: Read,
    W: Write,
{
    assert!(buf.len() >= 64 + 64);
    let blk_len = buf.len() - 64;

    let n = src.read_fully(buf)?;
    if n < 64 {
        return Err(Error::BadDecrypt);
    }

    let mut bs = [0u8; 32];
    bs.copy_from_slice(&buf[..32]);
    let pub_ephemeral = PublicKey::from(bs);
    let ikm = prv_key.diffie_hellman(&pub_ephemeral);

    let mut decryptor = CryptorCore::with_ikm(ikm.as_bytes()).decryptor();

    let tail = if n < buf.len() {
        decryptor.process_write(&mut buf[32..n - 32], dst)?;
        n
    } else {
        decryptor.process_write(&mut buf[32..blk_len + 32], dst)?;
        loop {
            buf.copy_within(blk_len + 32.., 32);
            let n = src.read_fully(&mut buf[64..])?;
            if n < blk_len {
                decryptor.process_write(&mut buf[32..n + 32], dst)?;
                break n + 64;
            } else {
                decryptor.process_write(&mut buf[32..blk_len + 32], dst)?;
            }
        }
    };
    if decryptor.finalize().code().as_ref() == &buf[tail - 32..tail] {
        Ok(())
    } else {
        Err(Error::BadDecrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_next(rand: &mut u32) -> u32 {
        *rand = rand.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        *rand
    }

    fn seq_fill(buf: &mut [u8]) {
        let mut rand: u32 = 0;
        for b in buf {
            *b = rand_next(&mut rand) as u8;
        }
    }

    fn seq_clear(buf: &mut [u8]) {
        for b in buf {
            *b = 0;
        }
    }

    fn seq_test(buf: &[u8]) {
        let mut rand: u32 = 0;
        for b in buf {
            assert_eq!(*b, rand_next(&mut rand) as u8);
        }
    }

    #[test]
    fn test_engine_buffer_len() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let prv_key = StaticSecret::from([0u8; 32]);
        let pub_key = PublicKey::from(&prv_key);

        for buf_len in 128..2048 + 128 {
            let mut src = vec![0u8; 2048];
            let mut dst = vec![0u8; src.len() + 64];
            let mut buf = vec![0u8; buf_len];

            seq_fill(&mut src);

            encrypt_internal::<&[u8], &mut [u8]>(
                &mut src.as_ref(),
                &mut dst.as_mut(),
                &pub_key,
                buf.as_mut(),
            )?;

            seq_clear(&mut src);

            decrypt_internal::<&[u8], &mut [u8]>(
                &mut dst.as_ref(),
                &mut src.as_mut(),
                &prv_key,
                buf.as_mut(),
            )?;

            seq_test(&src);
        }
        Ok(())
    }

    #[test]
    fn test_engine_data_len() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let prv_key = StaticSecret::from([0u8; 32]);
        let pub_key = PublicKey::from(&prv_key);

        let mut buf = vec![0u8; 128];

        for src_len in 128..2048 {
            let mut src = vec![0u8; src_len];
            let mut dst = vec![0u8; src_len + 64];

            seq_fill(&mut src);

            encrypt_internal::<&[u8], &mut [u8]>(
                &mut src.as_ref(),
                &mut dst.as_mut(),
                &pub_key,
                buf.as_mut(),
            )?;

            seq_clear(&mut src);

            decrypt_internal::<&[u8], &mut [u8]>(
                &mut dst.as_ref(),
                &mut src.as_mut(),
                &prv_key,
                buf.as_mut(),
            )?;

            seq_test(&src);
        }
        Ok(())
    }
}
