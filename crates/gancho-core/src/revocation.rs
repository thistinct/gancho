//! Certificate revocation: fetching CRLs and OCSP responses, and checking
//! a certificate against them.
//!
//! Long-term validation (PAdES-B-LT) stores this evidence in the PDF so a
//! signature can still be checked once the CA's servers have moved on or
//! the certificate has expired. The network goes through [`Fetch`]; the
//! `http` feature provides `HttpFetch`.

use der::asn1::{Null, OctetString};
use der::{Decode, Encode};
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, CrlDistributionPoints, ExtendedKeyUsage};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspRequest, OcspResponse, OcspResponseStatus, Request,
    TbsRequest,
};

use crate::ca::{self, Hash};

const ID_AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";
const ID_KP_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
const ID_PKIX_OCSP_BASIC: &str = "1.3.6.1.5.5.7.48.1.1";
const ID_SHA1: der::oid::ObjectIdentifier = der::oid::ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

/// Downloads for revocation data: plain GETs for CRLs, POSTs for OCSP.
pub trait Fetch {
    fn get(&mut self, url: &str) -> Result<Vec<u8>, String>;
    fn post(&mut self, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>, String>;
}

/// [`Fetch`] over HTTP(S).
#[cfg(feature = "http")]
#[derive(Debug, Default)]
pub struct HttpFetch;

#[cfg(feature = "http")]
impl Fetch for HttpFetch {
    fn get(&mut self, url: &str) -> Result<Vec<u8>, String> {
        let mut resp = ureq::get(url).call().map_err(|e| format!("{url}: {e}"))?;
        read_body(url, resp.body_mut())
    }

    fn post(&mut self, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>, String> {
        let mut resp = ureq::post(url)
            .header("Content-Type", content_type)
            .send(body)
            .map_err(|e| format!("{url}: {e}"))?;
        read_body(url, resp.body_mut())
    }
}

#[cfg(feature = "http")]
fn read_body(url: &str, body: &mut ureq::Body) -> Result<Vec<u8>, String> {
    // A national CA's CRL lists every revoked card, so allow it to be big.
    body.with_config()
        .limit(64 * 1024 * 1024)
        .read_to_vec()
        .map_err(|e| format!("{url}: {e}"))
}

/// Where a revocation answer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Ocsp,
    Crl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Good,
    /// Revoked at this time (Unix seconds).
    Revoked(i64),
}

/// A verified statement about one certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding {
    pub source: Source,
    pub status: Status,
    /// When the CA made the statement (`thisUpdate`), Unix seconds.
    pub issued_at: i64,
}

/// Revocation evidence as stored in a PDF's DSS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    /// DER `OCSPResponse`.
    Ocsp(Vec<u8>),
    /// DER `CertificateList`.
    Crl(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RevocationError {
    #[error("the certificate names no CRL or OCSP server")]
    NoServer,
    #[error("could not get revocation data: {0}")]
    Unavailable(String),
}

/// The CRL distribution point URLs in `cert`.
pub fn crl_urls(cert: &Certificate) -> Vec<String> {
    let Ok(Some((_, points))) = cert.tbs_certificate.get::<CrlDistributionPoints>() else {
        return Vec::new();
    };
    points
        .0
        .iter()
        .filter_map(|p| match &p.distribution_point {
            Some(DistributionPointName::FullName(names)) => Some(names),
            _ => None,
        })
        .flatten()
        .filter_map(uri)
        .collect()
}

/// The OCSP responder URLs in `cert`'s authority information access.
pub fn ocsp_urls(cert: &Certificate) -> Vec<String> {
    let Ok(Some((_, aia))) = cert.tbs_certificate.get::<AuthorityInfoAccessSyntax>() else {
        return Vec::new();
    };
    aia.0
        .iter()
        .filter(|a| a.access_method.to_string() == ID_AD_OCSP)
        .filter_map(|a| uri(&a.access_location))
        .collect()
}

fn uri(name: &GeneralName) -> Option<String> {
    match name {
        GeneralName::UniformResourceIdentifier(u) => {
            let u = u.to_string();
            (u.starts_with("http://") || u.starts_with("https://")).then_some(u)
        }
        _ => None,
    }
}

/// Asks the certificate's OCSP responders, then its CRL distribution
/// points, and returns the first answer that checks out (signed by the
/// issuer and about this certificate), with what it says.
pub fn fetch(
    cert: &Certificate,
    issuer: &Certificate,
    fetch: &mut dyn Fetch,
) -> Result<(Evidence, Finding), RevocationError> {
    let mut problems = Vec::new();
    for url in ocsp_urls(cert) {
        let answer = ocsp_request(cert, issuer)
            .map_err(|e| e.to_string())
            .and_then(|req| fetch.post(&url, "application/ocsp-request", &req))
            .and_then(|resp| {
                let finding = check_ocsp(&resp, cert, issuer)?;
                Ok((Evidence::Ocsp(resp), finding))
            });
        match answer {
            Ok(a) => return Ok(a),
            Err(e) => problems.push(format!("{url}: {e}")),
        }
    }
    for url in crl_urls(cert) {
        let answer = fetch.get(&url).and_then(|crl| {
            let finding = check_crl(&crl, cert, issuer)?;
            Ok((Evidence::Crl(crl), finding))
        });
        match answer {
            Ok(a) => return Ok(a),
            Err(e) => problems.push(format!("{url}: {e}")),
        }
    }
    if problems.is_empty() {
        Err(RevocationError::NoServer)
    } else {
        Err(RevocationError::Unavailable(problems.join("; ")))
    }
}

/// What the stored evidence says about `cert`, preferring OCSP. `None`
/// when nothing there is about it (or nothing verifies).
pub fn check(
    cert: &Certificate,
    issuer: &Certificate,
    ocsps: &[Vec<u8>],
    crls: &[Vec<u8>],
) -> Option<Finding> {
    ocsps
        .iter()
        .filter_map(|r| check_ocsp(r, cert, issuer).ok())
        .max_by_key(|f| f.issued_at)
        .or_else(|| {
            crls.iter()
                .filter_map(|c| check_crl(c, cert, issuer).ok())
                .max_by_key(|f| f.issued_at)
        })
}

/// A DER `OCSPRequest` for one certificate, with a SHA-1 `CertID` as
/// responders universally accept.
pub fn ocsp_request(cert: &Certificate, issuer: &Certificate) -> Result<Vec<u8>, der::Error> {
    let req = OcspRequest {
        tbs_request: TbsRequest {
            request_list: vec![Request {
                req_cert: cert_id(Hash::Sha1, cert, issuer)?,
                single_request_extensions: None,
            }],
            ..Default::default()
        },
        optional_signature: None,
    };
    req.to_der()
}

fn cert_id(hash: Hash, cert: &Certificate, issuer: &Certificate) -> Result<CertId, der::Error> {
    let oid = match hash {
        Hash::Sha1 => ID_SHA1,
        Hash::Sha256 => der::oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
        Hash::Sha384 => der::oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2"),
        Hash::Sha512 => der::oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3"),
    };
    let key = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    Ok(CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(
            hash.digest(&[&issuer.tbs_certificate.subject.to_der()?]),
        )?,
        issuer_key_hash: OctetString::new(hash.digest(&[key]))?,
        serial_number: cert.tbs_certificate.serial_number.clone(),
    })
}

/// Checks a DER `OCSPResponse` about `cert`: successful, signed by the
/// issuer or by a responder the issuer authorized, and naming `cert`.
pub fn check_ocsp(
    response: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
) -> Result<Finding, String> {
    let basic = basic_response(response)?;
    let tbs = basic
        .tbs_response_data
        .to_der()
        .map_err(|e| e.to_string())?;
    let sig = basic
        .signature
        .as_bytes()
        .ok_or("malformed OCSP signature")?;
    let alg = basic.signature_algorithm.oid.to_string();
    let hash =
        Hash::from_rsa_signature_oid(&alg).ok_or(format!("unsupported OCSP signature {alg}"))?;
    let verifies = |signer: &Certificate| {
        ca::public_key(signer).is_ok_and(|k| ca::verify_rsa(hash, &k, &tbs, sig))
    };
    let delegated = basic.certs.iter().flatten().any(|r| {
        r.tbs_certificate.issuer == issuer.tbs_certificate.subject
            && ca::issued_by(r, issuer)
            && can_sign_ocsp(r)
            && verifies(r)
    });
    if !verifies(issuer) && !delegated {
        return Err("the OCSP answer is not signed by the certificate's CA".into());
    }
    for single in &basic.tbs_response_data.responses {
        let alg = single.cert_id.hash_algorithm.oid.to_string();
        let Some(hash) = Hash::from_digest_oid(&alg) else {
            continue;
        };
        if cert_id(hash, cert, issuer).is_ok_and(|id| {
            id.issuer_name_hash == single.cert_id.issuer_name_hash
                && id.issuer_key_hash == single.cert_id.issuer_key_hash
                && id.serial_number == single.cert_id.serial_number
        }) {
            let status = match &single.cert_status {
                CertStatus::Good(_) => Status::Good,
                CertStatus::Revoked(info) => {
                    Status::Revoked(info.revocation_time.0.to_unix_duration().as_secs() as i64)
                }
                CertStatus::Unknown(_) => {
                    return Err("the OCSP server does not know the certificate".into());
                }
            };
            return Ok(Finding {
                source: Source::Ocsp,
                status,
                issued_at: single.this_update.0.to_unix_duration().as_secs() as i64,
            });
        }
    }
    Err("the OCSP answer is about another certificate".into())
}

fn basic_response(response: &[u8]) -> Result<BasicOcspResponse, String> {
    let resp = OcspResponse::from_der(response).map_err(|e| format!("malformed OCSP: {e}"))?;
    if resp.response_status != OcspResponseStatus::Successful {
        return Err(format!("OCSP status {:?}", resp.response_status));
    }
    let bytes = resp.response_bytes.ok_or("empty OCSP answer")?;
    if bytes.response_type.to_string() != ID_PKIX_OCSP_BASIC {
        return Err("unsupported OCSP answer type".into());
    }
    BasicOcspResponse::from_der(bytes.response.as_bytes())
        .map_err(|e| format!("malformed OCSP: {e}"))
}

/// Certificates carried inside an OCSP response (delegated responders),
/// DER; a verifier needs them to check the responder.
pub fn ocsp_certificates(response: &[u8]) -> Vec<Vec<u8>> {
    basic_response(response)
        .ok()
        .and_then(|b| b.certs)
        .unwrap_or_default()
        .iter()
        .filter_map(|c| c.to_der().ok())
        .collect()
}

fn can_sign_ocsp(cert: &Certificate) -> bool {
    cert.tbs_certificate
        .get::<ExtendedKeyUsage>()
        .ok()
        .flatten()
        .is_some_and(|(_, eku)| eku.0.iter().any(|o| o.to_string() == ID_KP_OCSP_SIGNING))
}

/// Checks a DER CRL against `cert`: issued and signed by `issuer`, and
/// whether it lists `cert`.
pub fn check_crl(crl: &[u8], cert: &Certificate, issuer: &Certificate) -> Result<Finding, String> {
    let list = CertificateList::from_der(crl).map_err(|e| format!("malformed CRL: {e}"))?;
    let tbs = &list.tbs_cert_list;
    if tbs.issuer != issuer.tbs_certificate.subject
        || cert.tbs_certificate.issuer != issuer.tbs_certificate.subject
    {
        return Err("the CRL is from another CA".into());
    }
    let alg = list.signature_algorithm.oid.to_string();
    let hash =
        Hash::from_rsa_signature_oid(&alg).ok_or(format!("unsupported CRL signature {alg}"))?;
    let signed = tbs.to_der().map_err(|e| e.to_string())?;
    let sig = list.signature.as_bytes().ok_or("malformed CRL signature")?;
    let key = ca::public_key(issuer).map_err(|_| "unsupported CA key")?;
    if !ca::verify_rsa(hash, &key, &signed, sig) {
        return Err("the CRL signature does not verify".into());
    }
    let status = tbs
        .revoked_certificates
        .iter()
        .flatten()
        .find(|r| r.serial_number == cert.tbs_certificate.serial_number)
        .map_or(Status::Good, |r| {
            Status::Revoked(r.revocation_date.to_unix_duration().as_secs() as i64)
        });
    Ok(Finding {
        source: Source::Crl,
        status,
        issued_at: tbs.this_update.to_unix_duration().as_secs() as i64,
    })
}
