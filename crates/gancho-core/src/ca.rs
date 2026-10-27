//! Certificate authorities behind the cédula, and certificate path building.
//!
//! Cédula signing certificates are issued by "AC Ministerio del Interior",
//! which is in turn certified by "AC Raíz Nacional de Uruguay" (ACRN, run by
//! AGESIC/UCE). Embedding both in each signature lets a validator connect the
//! signer to the national root without fetching anything.
//!
//! "Autoridad Certificadora TuID" (ANTEL) is bundled too, so signatures
//! made with TuID, whose PDFs carry only the signer's certificate, can be
//! traced to the same root.

use der::{Decode, Encode};
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use x509_cert::Certificate;
use x509_cert::ext::pkix::BasicConstraints;

/// CA certificates (DER) shipped with gancho: the Ministerio del Interior
/// CA that issues cédula certificates, the TuID CA, and the national root
/// (ACRN). See `certs/README.md` for sources and fingerprints.
pub const BUNDLED: &[&[u8]] = &[MINISTERIO_DEL_INTERIOR, TUID, RAIZ_NACIONAL];

pub const MINISTERIO_DEL_INTERIOR: &[u8] = include_bytes!("../certs/mica.der");
pub const RAIZ_NACIONAL: &[u8] = include_bytes!("../certs/acrn.der");
pub const TUID: &[u8] = include_bytes!("../certs/tuid.der");

/// Bundled certificates that are roots (self-signed), for use as trust
/// anchors.
pub fn bundled_roots() -> Vec<&'static [u8]> {
    BUNDLED.iter().copied().filter(|der| is_root(der)).collect()
}

/// Walks from `cert_der` up through `pool`, returning the issuing
/// certificates in order (issuer first, root last). Each link must be
/// signed by the next. Stops at a self-signed certificate or when no
/// issuer is found, so the result may be partial or empty.
pub fn issuer_chain(cert_der: &[u8], pool: &[&[u8]]) -> Vec<Vec<u8>> {
    let pool: Vec<(Vec<u8>, Certificate)> = pool
        .iter()
        .filter_map(|der| Some((der.to_vec(), Certificate::from_der(der).ok()?)))
        .collect();
    let Ok(mut current) = Certificate::from_der(cert_der) else {
        return Vec::new();
    };
    let mut chain = Vec::new();
    // Real paths are two or three long; the bound guards against loops.
    while chain.len() < 8 && !is_self_signed(&current) {
        let Some((der, issuer)) = pool.iter().find(|(_, c)| {
            c.tbs_certificate.subject == current.tbs_certificate.issuer
                && is_ca(c)
                && issued_by(&current, c)
        }) else {
            break;
        };
        if chain.contains(der) {
            break;
        }
        chain.push(der.clone());
        current = issuer.clone();
    }
    chain
}

/// Whether the certificate may issue others (`basicConstraints` cA). Without
/// this check any signer could mint certificates under their own name.
pub fn is_ca(cert: &Certificate) -> bool {
    cert.tbs_certificate
        .get::<BasicConstraints>()
        .ok()
        .flatten()
        .is_some_and(|(_, bc)| bc.ca)
}

/// Whether `der` is a self-signed (root) certificate.
pub fn is_root(der: &[u8]) -> bool {
    Certificate::from_der(der).is_ok_and(|c| is_self_signed(&c))
}

pub fn is_self_signed(cert: &Certificate) -> bool {
    cert.tbs_certificate.subject == cert.tbs_certificate.issuer && issued_by(cert, cert)
}

/// Whether `issuer`'s key verifies the signature on `cert`. Only RSA
/// PKCS#1 v1.5 with SHA-1/256/384/512 is understood, which covers the
/// Uruguayan PKI.
pub fn issued_by(cert: &Certificate, issuer: &Certificate) -> bool {
    let Ok(tbs) = cert.tbs_certificate.to_der() else {
        return false;
    };
    let Some(sig) = cert.signature.as_bytes() else {
        return false;
    };
    let Ok(key) = public_key(issuer) else {
        return false;
    };
    verify_rsa(&cert.signature_algorithm.oid.to_string(), &key, &tbs, sig)
}

pub(crate) fn public_key(cert: &Certificate) -> Result<RsaPublicKey, ()> {
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| ())?;
    RsaPublicKey::from_public_key_der(&spki).map_err(|_| ())
}

/// Verifies an RSA PKCS#1 v1.5 signature named by its X.509/CMS algorithm
/// OID. `rsaEncryption` (as CMS uses it) is taken to mean SHA-256.
pub(crate) fn verify_rsa(alg_oid: &str, key: &RsaPublicKey, msg: &[u8], sig: &[u8]) -> bool {
    let Ok(sig) = Signature::try_from(sig) else {
        return false;
    };
    let key = key.clone();
    match alg_oid {
        "1.2.840.113549.1.1.5" => VerifyingKey::<sha1::Sha1>::new(key)
            .verify(msg, &sig)
            .is_ok(),
        "1.2.840.113549.1.1.11" | "1.2.840.113549.1.1.1" => VerifyingKey::<sha2::Sha256>::new(key)
            .verify(msg, &sig)
            .is_ok(),
        "1.2.840.113549.1.1.12" => VerifyingKey::<sha2::Sha384>::new(key)
            .verify(msg, &sig)
            .is_ok(),
        "1.2.840.113549.1.1.13" => VerifyingKey::<sha2::Sha512>::new(key)
            .verify(msg, &sig)
            .is_ok(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn fingerprint(der: &[u8]) -> String {
        Sha256::digest(der)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect()
    }

    #[test]
    fn bundled_certificates_are_the_published_ones() {
        assert_eq!(
            fingerprint(RAIZ_NACIONAL),
            "5533A0401F612C688EBCE5BF53F2EC14A734EB178BFAE00E50E85DAE6723078A"
        );
        assert_eq!(
            fingerprint(MINISTERIO_DEL_INTERIOR),
            "A29CAD5C89AA49CFF81F17F45C42FD44685510246D9AB5D031448E2FDA2517BE"
        );
        assert_eq!(
            fingerprint(TUID),
            "F7C2D302FC18F29CAD0D2B60E4FC9EB564781F8D3F49693CE38C3B2CAE2F091E"
        );
    }

    #[test]
    fn intermediates_chain_to_the_national_root() {
        assert_eq!(bundled_roots(), vec![RAIZ_NACIONAL]);
        assert_eq!(
            issuer_chain(MINISTERIO_DEL_INTERIOR, BUNDLED),
            vec![RAIZ_NACIONAL.to_vec()]
        );
        assert_eq!(issuer_chain(TUID, BUNDLED), vec![RAIZ_NACIONAL.to_vec()]);
    }
}
