//! Detached CAdES signatures (`.p7s`) for files of any type.
//!
//! The signature lives in its own file next to the original, which stays
//! untouched: `contrato.docx` is signed into `contrato.docx.p7s`. This is
//! the CAdES baseline B-B profile (ETSI EN 319 122-1), or B-T with a
//! timestamp; [`crate::verify::verify_detached`] checks one.

use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::Signer;
use crate::cms::{CmsError, cades_detached};
use crate::tsp::TimestampAuthority;

/// What to put in a detached signature.
#[derive(Debug, Clone, Default)]
pub struct DetachedOptions {
    /// Signing time recorded in the signature; defaults to now.
    pub time: Option<SystemTime>,
    /// Extra certificates (DER) to embed, typically the issuing CA chain.
    pub chain: Vec<Vec<u8>>,
}

/// Signs `content` and returns the DER `.p7s` signature (CAdES-B-B, or
/// CAdES-B-T with a `tsa`).
pub fn sign_detached(
    content: &[u8],
    signer: &mut dyn Signer,
    options: &DetachedOptions,
    tsa: Option<&mut dyn TimestampAuthority>,
) -> Result<Vec<u8>, CmsError> {
    let digest: [u8; 32] = Sha256::digest(content).into();
    sign_detached_digest(&digest, signer, options, tsa)
}

/// Like [`sign_detached`], for content already hashed with SHA-256 (for
/// example a large file streamed through a hasher).
pub fn sign_detached_digest(
    digest: &[u8; 32],
    signer: &mut dyn Signer,
    options: &DetachedOptions,
    tsa: Option<&mut dyn TimestampAuthority>,
) -> Result<Vec<u8>, CmsError> {
    let time = options.time.unwrap_or_else(SystemTime::now);
    cades_detached(signer, digest, &options.chain, time, tsa)
}

/// Whether `bytes` start like a PDF file (`%PDF-`, which readers accept
/// within the first kilobyte).
pub fn looks_like_pdf(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(1024)]
        .windows(5)
        .any(|w| w == b"%PDF-")
}
