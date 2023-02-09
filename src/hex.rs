use super::error::{Error, Result};

pub fn hex_decode(s: &str, buf: &mut [u8]) -> Result<()> {
    let bs = s.as_bytes();
    if bs.len() != buf.len() * 2 {
        return Err(Error::BadHex(format!(
            "invalid length (not {})",
            buf.len() * 2
        )));
    }
    for i in 0..32 {
        buf[i] = hex(bs[i * 2])? * 16 + hex(bs[i * 2 + 1])?;
    }
    Ok(())
}

fn hex(b: u8) -> Result<u8> {
    if (b'0'..=b'9').contains(&b) {
        Ok(b - b'0')
    } else if (b'A'..=b'F').contains(&b) {
        Ok(b - b'A' + 10)
    } else if (b'a'..=b'f').contains(&b) {
        Ok(b - b'a' + 10)
    } else {
        Err(Error::BadHex(format!("invalid character: {}", b as char)))
    }
}
