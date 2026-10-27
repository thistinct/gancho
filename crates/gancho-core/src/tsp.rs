//! RFC 3161 timestamps for signatures (PAdES baseline B-T).
//!
//! A timestamp authority (TSA) signs the hash of our signature value
//! together with its own clock reading. The token goes into the CMS
//! `SignerInfo` as the unsigned `signature-time-stamp` attribute, which
//! proves the signature existed at that time, so it stays verifiable
//! after the signer's certificate expires.
//!
//! The HTTP exchange goes through [`TimestampAuthority`]; the `http`
//! feature provides `HttpTsa`, so the core stays free of networking
//! unless asked.

use std::time::{SystemTime, UNIX_EPOCH};

use cmpv2::status::PkiStatus;
use der::asn1::{Int, OctetString};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use x509_cert::spki::AlgorithmIdentifier;
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion, TstInfo};

const ID_SHA256: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// Something that can deliver a DER `TimeStampReq` to a TSA and return its
/// DER `TimeStampResp`, typically an HTTP POST with content type
/// `application/timestamp-query`.
pub trait TimestampAuthority {
    fn post(&mut self, request: &[u8]) -> Result<Vec<u8>, String>;
}

#[derive(Debug, thiserror::Error)]
pub enum TspError {
    #[error("could not reach the timestamp server: {0}")]
    Transport(String),
    #[error("the timestamp server's answer is not readable: {0}")]
    Malformed(String),
    #[error("the timestamp server refused the request (status {0})")]
    Refused(String),
    #[error("the timestamp server answered for different data")]
    Mismatch,
}

impl From<der::Error> for TspError {
    fn from(e: der::Error) -> Self {
        TspError::Malformed(e.to_string())
    }
}

/// A timestamp server reached over HTTP(S), e.g.
/// `http://timestamp.digicert.com`.
#[cfg(feature = "http")]
pub struct HttpTsa(pub String);

#[cfg(feature = "http")]
impl TimestampAuthority for HttpTsa {
    fn post(&mut self, request: &[u8]) -> Result<Vec<u8>, String> {
        let url = &self.0;
        let mut resp = ureq::post(url)
            .header("Content-Type", "application/timestamp-query")
            .send(request)
            .map_err(|e| format!("{url}: {e}"))?;
        resp.body_mut()
            .with_config()
            .limit(1024 * 1024)
            .read_to_vec()
            .map_err(|e| format!("{url}: {e}"))
    }
}

/// Gets a timestamp token (DER `ContentInfo`) over the SHA-256 of `data`.
pub fn fetch_token(tsa: &mut dyn TimestampAuthority, data: &[u8]) -> Result<Vec<u8>, TspError> {
    let imprint: [u8; 32] = Sha256::digest(data).into();
    let nonce = nonce(&imprint);
    let request = request_der(&imprint, nonce)?;
    let response = tsa.post(&request).map_err(TspError::Transport)?;
    token_from_response(&response, &imprint, nonce)
}

/// A `TimeStampReq` for a SHA-256 imprint, asking for the TSA certificate
/// to be included so the token can be verified on its own.
pub fn request_der(imprint: &[u8; 32], nonce: u64) -> Result<Vec<u8>, TspError> {
    Ok(TimeStampReq {
        version: TspVersion::V1,
        message_imprint: MessageImprint {
            hash_algorithm: AlgorithmIdentifier {
                oid: ID_SHA256,
                parameters: None,
            },
            hashed_message: OctetString::new(imprint.to_vec())?,
        },
        req_policy: None,
        nonce: Some(Int::new(&nonce_bytes(nonce))?),
        cert_req: true,
        extensions: None,
    }
    .to_der()?)
}

/// Checks a `TimeStampResp` against what was asked and returns its token.
pub fn token_from_response(
    response: &[u8],
    imprint: &[u8; 32],
    nonce: u64,
) -> Result<Vec<u8>, TspError> {
    let resp = TimeStampResp::from_der(response)?;
    if !matches!(
        resp.status.status,
        PkiStatus::Accepted | PkiStatus::GrantedWithMods
    ) {
        return Err(TspError::Refused(format!("{:?}", resp.status.status)));
    }
    let token = resp
        .time_stamp_token
        .ok_or(TspError::Malformed("no token".into()))?;
    let sd: cms::signed_data::SignedData = token.content.decode_as()?;
    let tst_der = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(TspError::Malformed("empty token".into()))?
        .decode_as::<OctetString>()?;
    let tst = TstInfo::from_der(tst_der.as_bytes())?;
    if tst.message_imprint.hashed_message.as_bytes() != imprint
        || tst.message_imprint.hash_algorithm.oid != ID_SHA256
        || tst.nonce.as_ref().map(Int::as_bytes) != Some(nonce_bytes(nonce).as_slice())
    {
        return Err(TspError::Mismatch);
    }
    Ok(token.to_der()?)
}

/// Not secret, only needs to differ between requests.
fn nonce(imprint: &[u8; 32]) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    // Positive and without a leading zero byte, so its DER INTEGER
    // encoding is exactly these eight bytes.
    let mixed = now ^ u64::from_be_bytes(imprint[..8].try_into().unwrap());
    (mixed & 0x7FFF_FFFF_FFFF_FFFF) | 0x4000_0000_0000_0000
}

fn nonce_bytes(nonce: u64) -> [u8; 8] {
    nonce.to_be_bytes()
}
