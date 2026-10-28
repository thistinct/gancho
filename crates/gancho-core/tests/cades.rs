//! Detached CAdES (`.p7s`) signatures over arbitrary files: signing with a
//! software key under the test CA hierarchy, checking with
//! `verify_detached`, and interoperating with `openssl cms`.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

use gancho_core::ca::issuer_chain;
use gancho_core::cades::{DetachedOptions, looks_like_pdf, sign_detached};
use gancho_core::verify::{IntegrityError, VerifyError, parse_pdf_date, verify_detached};
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

/// Not a PDF: a spreadsheet's worth of arbitrary bytes.
const CONTENT: &[u8] = b"nombre,monto\nAna,100\nLuis,250\n\x00\xff binario";

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

fn options() -> DetachedOptions {
    DetachedOptions {
        chain: issuer_chain(LEAF, &[ROOT, INTERMEDIATE]),
        ..Default::default()
    }
}

fn sign(content: &[u8], options: &DetachedOptions) -> Vec<u8> {
    let mut signer = SoftSigner(RsaPrivateKey::from_pkcs8_pem(LEAF_KEY).unwrap());
    sign_detached(content, &mut signer, options, None).unwrap()
}

#[test]
fn detached_signature_verifies() {
    let p7s = sign(CONTENT, &options());
    let r = verify_detached(&p7s, Some(CONTENT), &[ROOT], &[]).unwrap();
    assert_eq!(r.integrity, Ok(()));
    assert!(r.trusted);
    assert_eq!(r.valid_at_signing_time, Some(true));
    assert!(r.is_valid());
    assert!(r.signer.as_deref().unwrap().contains("PRUEBA FIRMANTE"));
    assert_eq!(r.chain.len(), 2);
    assert!(r.signed_at.is_some());
}

#[test]
fn records_the_signing_time() {
    let t = UNIX_EPOCH + Duration::from_secs(1_792_929_845);
    let p7s = sign(
        CONTENT,
        &DetachedOptions {
            time: Some(t),
            ..options()
        },
    );
    let r = verify_detached(&p7s, Some(CONTENT), &[ROOT], &[]).unwrap();
    assert_eq!(r.signed_at.as_deref(), Some("D:20261025120405Z"));
    assert_eq!(
        parse_pdf_date(r.signed_at.as_deref().unwrap()),
        Some(1_792_929_845)
    );
    // Before the test certificate was issued (2026-10-27).
    assert_eq!(r.valid_at_signing_time, Some(false));
    assert!(!r.is_valid());
}

#[test]
fn changed_file_is_detected() {
    let p7s = sign(CONTENT, &options());
    let mut changed = CONTENT.to_vec();
    changed[14] = b'X';
    let r = verify_detached(&p7s, Some(&changed), &[ROOT], &[]).unwrap();
    assert_eq!(r.integrity, Err(IntegrityError::Digest));
    assert!(!r.is_valid());
}

#[test]
fn needs_the_original_file() {
    let p7s = sign(CONTENT, &options());
    assert!(matches!(
        verify_detached(&p7s, None, &[ROOT], &[]),
        Err(VerifyError::NoContent)
    ));
}

#[test]
fn garbage_is_not_a_signature() {
    let r = verify_detached(b"hola", Some(CONTENT), &[ROOT], &[]).unwrap();
    assert!(matches!(r.integrity, Err(IntegrityError::Cms(_))));
}

#[test]
fn unknown_root_is_not_trusted() {
    let p7s = sign(CONTENT, &options());
    let r = verify_detached(&p7s, Some(CONTENT), &[], &[]).unwrap();
    assert_eq!(r.integrity, Ok(()));
    assert!(!r.trusted);
}

#[test]
fn pdfs_can_be_signed_detached_too() {
    assert!(looks_like_pdf(SAMPLE));
    assert!(!looks_like_pdf(CONTENT));
    let p7s = sign(SAMPLE, &options());
    assert!(
        verify_detached(&p7s, Some(SAMPLE), &[ROOT], &[])
            .unwrap()
            .is_valid()
    );
}

fn scratch(name: &str) -> Option<PathBuf> {
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("skipping: openssl not installed");
        return None;
    }
    let dir = std::env::temp_dir().join(format!("gancho-cades-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for f in [
        "chain-root.der",
        "chain-leaf.der",
        "chain-intermediate.der",
        "chain-leaf-key.pem",
    ] {
        std::fs::copy(fixtures.join(f), dir.join(f)).unwrap();
    }
    std::fs::write(dir.join("datos.csv"), CONTENT).unwrap();
    Some(dir)
}

fn openssl(dir: &PathBuf, args: &[&str]) -> std::process::Output {
    let out = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// Our `.p7s` checks out with `openssl cms -verify`, against the test root.
#[test]
fn openssl_accepts_our_signature() {
    let Some(dir) = scratch("ours") else { return };
    std::fs::write(dir.join("datos.csv.p7s"), sign(CONTENT, &options())).unwrap();
    openssl(
        &dir,
        &[
            "x509",
            "-inform",
            "DER",
            "-in",
            "chain-root.der",
            "-out",
            "root.pem",
        ],
    );
    openssl(
        &dir,
        &[
            "cms",
            "-verify",
            "-binary",
            "-inform",
            "DER",
            "-in",
            "datos.csv.p7s",
            "-content",
            "datos.csv",
            "-CAfile",
            "root.pem",
            "-purpose",
            "any",
            "-out",
            "/dev/null",
        ],
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A detached signature made by `openssl cms -sign` (PEM, as openssl writes
/// it) verifies with ours, and so does an attached one without the file.
#[test]
fn we_accept_openssl_signatures() {
    let Some(dir) = scratch("theirs") else { return };
    openssl(
        &dir,
        &[
            "x509",
            "-inform",
            "DER",
            "-in",
            "chain-leaf.der",
            "-out",
            "leaf.pem",
        ],
    );
    openssl(
        &dir,
        &[
            "x509",
            "-inform",
            "DER",
            "-in",
            "chain-intermediate.der",
            "-out",
            "int.pem",
        ],
    );
    for (flags, out) in [
        (&["-binary"][..], "detached.p7s"),
        (&["-nodetach", "-binary"][..], "attached.p7s"),
    ] {
        let mut args = vec![
            "cms",
            "-sign",
            "-in",
            "datos.csv",
            "-signer",
            "leaf.pem",
            "-inkey",
            "chain-leaf-key.pem",
            "-certfile",
            "int.pem",
            "-md",
            "sha256",
            "-outform",
            "PEM",
            "-out",
            out,
        ];
        args.extend_from_slice(flags);
        openssl(&dir, &args);
    }
    let detached = std::fs::read(dir.join("detached.p7s")).unwrap();
    let r = verify_detached(&detached, Some(CONTENT), &[ROOT], &[]).unwrap();
    assert!(r.is_valid(), "{r:?}");
    let attached = std::fs::read(dir.join("attached.p7s")).unwrap();
    let r = verify_detached(&attached, None, &[ROOT], &[]).unwrap();
    assert!(r.is_valid(), "{r:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
