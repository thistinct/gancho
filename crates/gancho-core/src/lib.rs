//! Signing-device–agnostic core of open-gancho.
//!
//! The PDF/PAdES and CMS code lives here and only talks to a [`Signer`], so it
//! can be tested with a software key and driven by the cédula in production.

/// Something that holds a certificate and can produce RSA PKCS#1 v1.5
/// signatures with the matching private key.
pub trait Signer {
    /// DER-encoded X.509 signing certificate.
    fn certificate_der(&self) -> &[u8];

    /// Sign `data` with RSASSA-PKCS1-v1_5 / SHA-256. The device hashes `data`
    /// itself, so callers pass the bytes to be signed (for CMS, the DER of the
    /// signed attributes), not a digest.
    fn sign_sha256_rsa(&mut self, data: &[u8]) -> Result<Vec<u8>, SignError>;
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("wrong PIN ({0})")]
    WrongPin(String),
    #[error("PIN is blocked")]
    PinBlocked,
    #[error("signing device error: {0}")]
    Device(String),
}
