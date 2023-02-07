use super::error::{Error, Result};

use simple_asn1::{ASN1Block, BigInt, BigUint, OID};

// ASN1 DER import/ export functions.
// https://tools.ietf.org/html/rfc8410
// https://tools.ietf.org/html/rfc5958

pub fn import_pub(bs: &[u8]) -> Result<[u8; 32]> {
    if let [ASN1Block::Sequence(_, subject_public_key_info)] = simple_asn1::from_der(bs)
        .map_err(|u| Error::KeyImport(u.to_string()))?
        .as_slice()
    {
        if let [ASN1Block::Sequence(_, algorithm), ASN1Block::BitString(_, 256, subject_public_key)] =
            subject_public_key_info.as_slice()
        {
            if let [ASN1Block::ObjectIdentifier(_, oid)] = algorithm.as_slice() {
                if oid == oid_x25519() {
                    let mut bs = [0u8; 32];
                    bs.copy_from_slice(&subject_public_key);
                    return Ok(bs);
                }
                return Err(Error::KeyImport("unsupported public key type".to_owned()));
            }
        }
    }
    Err(Error::KeyImport(
        "invalid/ unsupported public key".to_owned(),
    ))
}

pub fn export_pub(bs: &[u8; 32]) -> Vec<u8> {
    let algorithm = ASN1Block::Sequence(0, vec![ASN1Block::ObjectIdentifier(0, oid_x25519())]);
    let subject_public_key = ASN1Block::BitString(0, 256, bs.to_vec());
    let block = ASN1Block::Sequence(0, vec![algorithm, subject_public_key]);
    simple_asn1::to_der(&block).expect("internal error")
}

pub fn import_prv(bs: &[u8]) -> Result<[u8; 32]> {
    if let [ASN1Block::Sequence(_, private_key_info)] = simple_asn1::from_der(bs)
        .map_err(|u| Error::KeyImport(u.to_string()))?
        .as_slice()
    {
        if let [ASN1Block::Integer(_, version), ASN1Block::Sequence(_, private_key_algorithm), ASN1Block::OctetString(_, private_key)] =
            private_key_info.as_slice()
        {
            if version == &BigInt::from(0) {
                if let [ASN1Block::ObjectIdentifier(_, oid)] = private_key_algorithm.as_slice() {
                    if oid == oid_x25519() {
                        return import_curve_prv_key(&private_key);
                    } else {
                        return Err(Error::KeyImport("unsupported private key type".to_owned()));
                    }
                }
            } else {
                return Err(Error::KeyImport(format!(
                    "unsupported private key version: {}",
                    version
                )));
            }
        }
    }
    Err(Error::KeyImport(
        "invalid/ unsupported private key".to_owned(),
    ))
}

pub fn export_prv(bs: &[u8; 32]) -> Vec<u8> {
    let version = ASN1Block::Integer(0, BigInt::from(0));
    let private_key_algorithm =
        ASN1Block::Sequence(0, vec![ASN1Block::ObjectIdentifier(0, oid_x25519())]);
    let private_key = ASN1Block::OctetString(0, export_curve_prv_key(bs));
    let block = ASN1Block::Sequence(0, vec![version, private_key_algorithm, private_key]);
    simple_asn1::to_der(&block).expect("internal error")
}

fn import_curve_prv_key(bs: &[u8]) -> Result<[u8; 32]> {
    if let [ASN1Block::OctetString(_, private_key)] = simple_asn1::from_der(bs)
        .map_err(|u| Error::KeyImport(u.to_string()))?
        .as_slice()
    {
        let mut bs = [0u8; 32];
        bs.copy_from_slice(&private_key);
        return Ok(bs);
    }
    Err(Error::KeyImport(
        "invalid/ unsupported curve private key".to_owned(),
    ))
}

fn export_curve_prv_key(key: &[u8; 32]) -> Vec<u8> {
    let block = ASN1Block::OctetString(0, key.to_vec());
    simple_asn1::to_der(&block).expect("internal error")
}

fn oid_x25519() -> OID {
    simple_asn1::oid!(1, 3, 101, 110)
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    const DER_PUB_KEY: [u8; 44] = hex!(
        "302A300506032B656E032100884FC0E9
         63FE2D853956DB594E1FEA78A1204E18
         FEC2CFF87D0409649D84C162"
    );

    const RAW_PUB_KEY: [u8; 32] = hex!(
        "884FC0E963FE2D853956DB594E1FEA78
         A1204E18FEC2CFF87D0409649D84C162"
    );

    const DER_PRV_KEY: [u8; 48] = hex!(
        "302E020100300506032B656E04220420
         1859597C2529D9D1085BEB2DBE4DFB8A
         20901650E5A1B9C434246405C4EE1C4E"
    );

    const RAW_PRV_KEY: [u8; 32] = hex!(
        "1859597C2529D9D1085BEB2DBE4DFB8A
         20901650E5A1B9C434246405C4EE1C4E"
    );

    #[test]
    fn test_import_pub() {
        let key = import_pub(&DER_PUB_KEY).unwrap();
        assert_eq!(key, RAW_PUB_KEY);
    }

    #[test]
    fn test_export_pub() {
        let der = export_pub(&RAW_PUB_KEY);
        assert_eq!(DER_PUB_KEY.as_ref(), der.as_slice());
    }

    #[test]
    fn test_import_prv() {
        let key = import_prv(&DER_PRV_KEY).unwrap();
        assert_eq!(key, RAW_PRV_KEY);
    }

    #[test]
    fn test_export_prv() {
        let der = export_prv(&RAW_PRV_KEY);
        assert_eq!(DER_PRV_KEY.as_ref(), der.as_slice());
    }
}
