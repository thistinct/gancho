//! Certificate authorities behind the cédula, and certificate path building.
//!
//! Cédula signing certificates are issued by "AC Ministerio del Interior",
//! which is in turn certified by "AC Raíz Nacional de Uruguay" (ACRN, run by
//! AGESIC/UCE). Embedding both in each signature lets a validator connect the
//! signer to the national root without fetching anything.

use der::{Decode, Encode};
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use x509_cert::Certificate;
use x509_cert::ext::pkix::BasicConstraints;

/// CA certificates (DER) shipped with gancho: intermediates and roots.
pub const BUNDLED: &[&[u8]] = &[];

/// Bundled certificates that are roots (self-signed), for use as trust
/// anchors.
pub fn bundled_roots() -> Vec<&'static [u8]> {
    BUNDLED.iter().copied().filter(|der| is_root(der)).collect()
}

/// What a person wants to know about a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSummary {
    /// Full subject, RFC 4514 style.
    pub subject: String,
    /// Subject common name, usually the person's name.
    pub common_name: Option<String>,
    pub issuer: String,
    /// Validity, Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
}

pub fn summarize(der: &[u8]) -> Option<CertificateSummary> {
    let c = Certificate::from_der(der).ok()?;
    let tbs = &c.tbs_certificate;
    Some(CertificateSummary {
        subject: tbs.subject.to_string(),
        common_name: crate::appearance::common_name(&c),
        issuer: tbs.issuer.to_string(),
        not_before: tbs.validity.not_before.to_unix_duration().as_secs() as i64,
        not_after: tbs.validity.not_after.to_unix_duration().as_secs() as i64,
    })
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
    Hash::from_rsa_signature_oid(&cert.signature_algorithm.oid.to_string())
        .is_some_and(|h| verify_rsa(h, &key, &tbs, sig))
}

pub(crate) fn public_key(cert: &Certificate) -> Result<RsaPublicKey, ()> {
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| ())?;
    RsaPublicKey::from_public_key_der(&spki).map_err(|_| ())
}

/// Hash functions that appear in the Uruguayan PKI and common TSAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    /// From a digest algorithm OID (`id-sha256`, ...).
    pub(crate) fn from_digest_oid(oid: &str) -> Option<Self> {
        Some(match oid {
            "1.3.14.3.2.26" => Hash::Sha1,
            "2.16.840.1.101.3.4.2.1" => Hash::Sha256,
            "2.16.840.1.101.3.4.2.2" => Hash::Sha384,
            "2.16.840.1.101.3.4.2.3" => Hash::Sha512,
            _ => return None,
        })
    }

    /// From an RSA signature algorithm OID (`sha256WithRSAEncryption`, ...).
    pub(crate) fn from_rsa_signature_oid(oid: &str) -> Option<Self> {
        Some(match oid {
            "1.2.840.113549.1.1.5" => Hash::Sha1,
            "1.2.840.113549.1.1.11" => Hash::Sha256,
            "1.2.840.113549.1.1.12" => Hash::Sha384,
            "1.2.840.113549.1.1.13" => Hash::Sha512,
            _ => return None,
        })
    }

    pub(crate) fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: sha2::Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut h = D::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().to_vec()
        }
        match self {
            Hash::Sha1 => run::<sha1::Sha1>(parts),
            Hash::Sha256 => run::<sha2::Sha256>(parts),
            Hash::Sha384 => run::<sha2::Sha384>(parts),
            Hash::Sha512 => run::<sha2::Sha512>(parts),
        }
    }
}

/// Verifies an RSA PKCS#1 v1.5 signature over `msg` hashed with `hash`.
pub(crate) fn verify_rsa(hash: Hash, key: &RsaPublicKey, msg: &[u8], sig: &[u8]) -> bool {
    let Ok(sig) = Signature::try_from(sig) else {
        return false;
    };
    let key = key.clone();
    match hash {
        Hash::Sha1 => VerifyingKey::<sha1::Sha1>::new(key).verify(msg, &sig),
        Hash::Sha256 => VerifyingKey::<sha2::Sha256>::new(key).verify(msg, &sig),
        Hash::Sha384 => VerifyingKey::<sha2::Sha384>::new(key).verify(msg, &sig),
        Hash::Sha512 => VerifyingKey::<sha2::Sha512>::new(key).verify(msg, &sig),
    }
    .is_ok()
}
