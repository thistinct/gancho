//! PAdES-B-T: timestamps from a local test TSA run with `openssl ts -reply`
//! (the tests are skipped when the openssl command is not installed).

use std::path::PathBuf;
use std::process::Command;

use gancho_core::ca::issuer_chain;
use gancho_core::cades::{DetachedOptions, sign_detached};
use gancho_core::pdf::{SignOptions, sign_pdf_timestamped};
use gancho_core::tsp::{TimestampAuthority, request_der, token_from_response};
use gancho_core::verify::{verify_detached, verify_pdf};
use gancho_core::{SignError, Signer};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer as _};
use sha2::Sha256;

const ROOT: &[u8] = include_bytes!("fixtures/chain-root.der");
const INTERMEDIATE: &[u8] = include_bytes!("fixtures/chain-intermediate.der");
const LEAF: &[u8] = include_bytes!("fixtures/chain-leaf.der");
const LEAF_KEY: &str = include_str!("fixtures/chain-leaf-key.pem");
const SAMPLE: &[u8] = include_bytes!("../../../samples/ejemplo.pdf");

struct SoftSigner(RsaPrivateKey);

impl Signer for SoftSigner {
    fn certificate_der(&self) -> &[u8] {
        LEAF
    }
    fn sign_sha256_rsa(&mut self, data: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(SigningKey::<Sha256>::new(self.0.clone())
            .sign(data)
            .to_vec())
    }
}

/// A TSA backed by `openssl ts -reply` in a scratch directory.
struct OpensslTsa {
    dir: PathBuf,
    /// Answer with this response instead (to test replays).
    replay: Option<Vec<u8>>,
}

impl OpensslTsa {
    fn new(name: &str) -> Option<Self> {
        if Command::new("openssl").arg("version").output().is_err() {
            eprintln!("skipping: openssl not installed");
            return None;
        }
        let dir = std::env::temp_dir().join(format!("gancho-tsa-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        for f in ["tsa.cnf", "tsa-cert.pem", "tsa-key.pem"] {
            std::fs::copy(fixtures.join(f), dir.join(f)).unwrap();
        }
        std::fs::write(dir.join("serial"), "01\n").unwrap();
        Some(Self { dir, replay: None })
    }
}

impl TimestampAuthority for OpensslTsa {
    fn post(&mut self, request: &[u8]) -> Result<Vec<u8>, String> {
        std::fs::write(self.dir.join("req.tsq"), request).unwrap();
        let out = Command::new("openssl")
            .current_dir(&self.dir)
            .args([
                "ts",
                "-reply",
                "-config",
                "tsa.cnf",
                "-queryfile",
                "req.tsq",
                "-out",
                "resp.tsr",
            ])
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).into_owned());
        }
        let resp = std::fs::read(self.dir.join("resp.tsr")).unwrap();
        Ok(self.replay.clone().unwrap_or(resp))
    }
}

impl Drop for OpensslTsa {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn sign_with(tsa: &mut OpensslTsa) -> Vec<u8> {
    let options = SignOptions {
        chain: issuer_chain(LEAF, &[ROOT, INTERMEDIATE]),
        ..Default::default()
    };
    let mut signer = SoftSigner(RsaPrivateKey::from_pkcs8_pem(LEAF_KEY).unwrap());
    sign_pdf_timestamped(SAMPLE, &mut signer, &options, Some(tsa)).unwrap()
}

#[test]
fn timestamped_signature_verifies() {
    let Some(mut tsa) = OpensslTsa::new("ok") else {
        return;
    };
    let signed = sign_with(&mut tsa);
    if let Some(dir) = std::env::var_os("GANCHO_TEST_OUT") {
        std::fs::write(PathBuf::from(dir).join("timestamped.pdf"), &signed).unwrap();
    }
    let r = &verify_pdf(&signed, &[ROOT], &[]).unwrap()[0];
    assert!(r.is_valid(), "{r:?}");
    let ts = r.timestamp.as_ref().expect("timestamp present");
    assert_eq!(ts.integrity, Ok(()));
    assert!(ts.trusted);
    assert!(
        ts.tsa
            .as_deref()
            .unwrap()
            .contains("PRUEBA SELLO DE TIEMPO")
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!((ts.time.unwrap() - now).abs() < 120);
}

#[test]
fn timestamped_detached_signature_verifies() {
    let Some(mut tsa) = OpensslTsa::new("detached") else {
        return;
    };
    let options = DetachedOptions {
        chain: issuer_chain(LEAF, &[ROOT, INTERMEDIATE]),
        ..Default::default()
    };
    let mut signer = SoftSigner(RsaPrivateKey::from_pkcs8_pem(LEAF_KEY).unwrap());
    let content = b"cualquier archivo";
    let p7s = sign_detached(content, &mut signer, &options, Some(&mut tsa)).unwrap();
    let r = verify_detached(&p7s, Some(content), &[ROOT], &[]).unwrap();
    assert!(r.is_valid(), "{r:?}");
    let ts = r.timestamp.as_ref().expect("timestamp present");
    assert_eq!(ts.integrity, Ok(()));
    assert!(ts.trusted);
}

#[test]
fn untrusted_tsa_is_reported() {
    let Some(mut tsa) = OpensslTsa::new("untrusted") else {
        return;
    };
    let signed = sign_with(&mut tsa);
    // The signer chain is trusted through --ca style intermediates but the
    // root is not an anchor, so neither the signer nor the TSA is trusted.
    let r = &verify_pdf(&signed, &[], &[]).unwrap()[0];
    let ts = r.timestamp.as_ref().unwrap();
    assert_eq!(ts.integrity, Ok(()));
    assert!(!ts.trusted);
}

#[test]
fn response_for_other_data_is_rejected() {
    let Some(mut tsa) = OpensslTsa::new("mismatch") else {
        return;
    };
    let req = request_der(&[7; 32], 0x4000_0000_0000_0001).unwrap();
    let resp = tsa.post(&req).unwrap();
    assert!(token_from_response(&resp, &[7; 32], 0x4000_0000_0000_0001).is_ok());
    assert!(token_from_response(&resp, &[8; 32], 0x4000_0000_0000_0001).is_err());
    assert!(token_from_response(&resp, &[7; 32], 0x4000_0000_0000_0002).is_err());
}

#[test]
fn replayed_timestamp_is_refused_when_signing() {
    let Some(mut tsa) = OpensslTsa::new("replay") else {
        return;
    };
    let first = sign_with(&mut tsa);
    // A TSA (or attacker in between) answering with an old token for a
    // different signature must not end up in the PDF.
    tsa.replay = Some(std::fs::read(tsa.dir.join("resp.tsr")).unwrap());
    let mut signer = SoftSigner(RsaPrivateKey::from_pkcs8_pem(LEAF_KEY).unwrap());
    let err = sign_pdf_timestamped(&first, &mut signer, &SignOptions::default(), Some(&mut tsa))
        .unwrap_err();
    assert!(err.to_string().contains("different data"), "{err}");
}
