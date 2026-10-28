//! Detached CMS `SignedData` in the shape PAdES baseline (B-B) expects
//! (ETSI EN 319 142-1, building on CAdES / ETSI EN 319 122-1).
//!
//! Signed attributes: `content-type` (id-data), `message-digest`, and
//! `signing-certificate-v2`. For PDFs there is deliberately no
//! `signing-time` attribute: PAdES carries the claimed signing time in the
//! signature dictionary's `/M` entry instead. Stand-alone CAdES signatures
//! ([`cades_detached`]) do carry `signing-time`, as CAdES-B-B requires.

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use std::time::{SystemTime, UNIX_EPOCH};

use der::asn1::{Any, GeneralizedTime, ObjectIdentifier, OctetString, SetOfVec, UtcTime};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::attr::Attribute;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Time;

use crate::tsp::{TimestampAuthority, TspError, fetch_token};
use crate::{SignError, Signer};

const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
const ID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const ID_SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

#[derive(Debug, thiserror::Error)]
pub enum CmsError {
    #[error("the signing certificate could not be parsed: {0}")]
    Certificate(der::Error),
    #[error("could not encode the signature: {0}")]
    Encode(#[from] der::Error),
    #[error(transparent)]
    Sign(#[from] SignError),
    #[error(transparent)]
    Timestamp(#[from] TspError),
    #[error("the signing time cannot be encoded")]
    Time,
}

/// Builds a DER `ContentInfo` holding a detached `SignedData` over content
/// whose SHA-256 digest is `content_digest`. `chain` holds extra certificates
/// to embed (intermediate CAs), DER encoded. With a `tsa`, the signature
/// value is timestamped (CAdES/PAdES B-T).
pub fn signed_data_detached(
    signer: &mut dyn Signer,
    content_digest: &[u8; 32],
    chain: &[Vec<u8>],
    tsa: Option<&mut dyn TimestampAuthority>,
) -> Result<Vec<u8>, CmsError> {
    build(signer, content_digest, chain, None, tsa)
}

/// Like [`signed_data_detached`], with a `signing-time` attribute: a
/// CAdES-B-B detached signature (`.p7s`) for content of any type, or
/// CAdES-B-T with a `tsa`.
pub fn cades_detached(
    signer: &mut dyn Signer,
    content_digest: &[u8; 32],
    chain: &[Vec<u8>],
    signing_time: SystemTime,
    tsa: Option<&mut dyn TimestampAuthority>,
) -> Result<Vec<u8>, CmsError> {
    build(signer, content_digest, chain, Some(signing_time), tsa)
}

fn build(
    signer: &mut dyn Signer,
    content_digest: &[u8; 32],
    chain: &[Vec<u8>],
    signing_time: Option<SystemTime>,
    tsa: Option<&mut dyn TimestampAuthority>,
) -> Result<Vec<u8>, CmsError> {
    let cert_der = signer.certificate_der().to_vec();
    let cert = Certificate::from_der(&cert_der).map_err(CmsError::Certificate)?;
    let sha256 = AlgorithmIdentifierOwned {
        oid: ID_SHA256,
        parameters: None,
    };

    let mut signed_attrs = SetOfVec::new();
    signed_attrs.insert(attribute(ID_CONTENT_TYPE, Any::encode_from(&ID_DATA)?))?;
    signed_attrs.insert(attribute(
        ID_MESSAGE_DIGEST,
        Any::encode_from(&OctetString::new(content_digest.to_vec())?)?,
    ))?;
    signed_attrs.insert(attribute(
        ID_SIGNING_CERTIFICATE_V2,
        Any::from_der(&signing_certificate_v2(&cert, &cert_der)?)?,
    ))?;
    if let Some(t) = signing_time {
        // RFC 5652 11.3: UTCTime through 2049, GeneralizedTime after.
        let since_epoch = t.duration_since(UNIX_EPOCH).map_err(|_| CmsError::Time)?;
        let since_epoch = std::time::Duration::from_secs(since_epoch.as_secs());
        let dt = der::DateTime::from_unix_duration(since_epoch).map_err(|_| CmsError::Time)?;
        let time = if dt.year() < 2050 {
            Time::from(UtcTime::from_date_time(dt)?)
        } else {
            Time::from(GeneralizedTime::from_date_time(dt))
        };
        signed_attrs.insert(attribute(ID_SIGNING_TIME, Any::encode_from(&time)?))?;
    }

    // The signature covers the DER of the attributes as a SET OF (tag 0x31),
    // not the [0] IMPLICIT form they take inside SignerInfo (RFC 5652 5.4).
    let signature = signer.sign_sha256_rsa(&signed_attrs.to_der()?)?;
    let unsigned_attrs = match tsa {
        Some(tsa) => {
            let token = fetch_token(tsa, &signature)?;
            let mut attrs = SetOfVec::new();
            attrs.insert(attribute(
                ID_SIGNATURE_TIME_STAMP_TOKEN,
                Any::from_der(&token)?,
            ))?;
            Some(attrs)
        }
        None => None,
    };

    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        }),
        digest_alg: sha256.clone(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: AlgorithmIdentifierOwned {
            oid: ID_RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        },
        signature: OctetString::new(signature)?,
        unsigned_attrs,
    };

    let mut certs = SetOfVec::new();
    certs.insert(CertificateChoices::Certificate(cert))?;
    for extra in chain {
        let c = Certificate::from_der(extra).map_err(CmsError::Certificate)?;
        certs.insert(CertificateChoices::Certificate(c))?;
    }

    let mut digest_algorithms = SetOfVec::new();
    digest_algorithms.insert(sha256)?;
    let mut signer_infos = SetOfVec::new();
    signer_infos.insert(signer_info)?;

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: ID_DATA,
            econtent: None,
        },
        certificates: Some(CertificateSet(certs)),
        crls: None,
        signer_infos: SignerInfos(signer_infos),
    };
    Ok(ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::encode_from(&signed_data)?,
    }
    .to_der()?)
}

fn attribute(oid: ObjectIdentifier, value: Any) -> Attribute {
    let mut values = SetOfVec::new();
    values.insert(value).expect("single value");
    Attribute { oid, values }
}

/// `SigningCertificateV2` (RFC 5035) with one `ESSCertIDv2`: the SHA-256 of
/// the certificate (the default hash, so `hashAlgorithm` is omitted) and its
/// issuer and serial number.
fn signing_certificate_v2(cert: &Certificate, cert_der: &[u8]) -> Result<Vec<u8>, der::Error> {
    let cert_hash = OctetString::new(Sha256::digest(cert_der).to_vec())?.to_der()?;
    // GeneralNames ::= SEQUENCE OF GeneralName; directoryName [4] EXPLICIT Name
    let general_names = tlv(0x30, &tlv(0xA4, &cert.tbs_certificate.issuer.to_der()?));
    let issuer_serial = tlv(
        0x30,
        &[general_names, cert.tbs_certificate.serial_number.to_der()?].concat(),
    );
    let ess_cert_id = tlv(0x30, &[cert_hash, issuer_serial].concat());
    Ok(tlv(0x30, &tlv(0x30, &ess_cert_id)))
}

/// DER tag-length-value.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}
