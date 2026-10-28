//! Long-term validation (PAdES-B-LT) and several signers, against the test
//! PKI in `fixtures/ltv` (see `make.sh` there). CRLs are served from
//! fixtures; OCSP answers come from `openssl ocsp`, and without the openssl
//! command the OCSP server just fails, so CRLs are used instead.

use std::path::PathBuf;
use std::process::Command;

use gancho_core::ca::issuer_chain;
use gancho_core::ltv::{LtvError, ValidationData, add_dss, add_validation_data};
use gancho_core::pdf::{PdfError, SignOptions, sign_pdf, sign_pdf_lt};
use gancho_core::revocation::{Fetch, Source, Status};
use gancho_core::verify::verify_pdf;
use gancho_core::{SignError, Signer};
use lopdf::{Document, IncrementalDocument, Object, Stream};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer as _};
use sha2::Sha256;

const ROOT: &[u8] = include_bytes!("fixtures/ltv/root.der");
const CA: &[u8] = include_bytes!("fixtures/ltv/ca.der");
const LEAF: &[u8] = include_bytes!("fixtures/ltv/leaf.der");
const LEAF_KEY: &str = include_str!("fixtures/ltv/leaf-key.pem");
const REVOKED: &[u8] = include_bytes!("fixtures/ltv/revoked.der");
const REVOKED_KEY: &str = include_str!("fixtures/ltv/revoked-key.pem");
const CRL_ONLY: &[u8] = include_bytes!("fixtures/ltv/crl-only.der");
const CRL_ONLY_KEY: &str = include_str!("fixtures/ltv/crl-only-key.pem");
const CA_CRL: &[u8] = include_bytes!("fixtures/ltv/ca.crl");
const ROOT_CRL: &[u8] = include_bytes!("fixtures/ltv/root.crl");
const SAMPLE: &[u8] = include_bytes!("../../../samples/ejemplo.pdf");

struct SoftSigner {
    key: RsaPrivateKey,
    cert: &'static [u8],
    calls: usize,
}

impl SoftSigner {
    fn new(cert: &'static [u8], key: &str) -> Self {
        Self {
            key: RsaPrivateKey::from_pkcs8_pem(key).unwrap(),
            cert,
            calls: 0,
        }
    }
}

impl Signer for SoftSigner {
    fn certificate_der(&self) -> &[u8] {
        self.cert
    }
    fn sign_sha256_rsa(&mut self, data: &[u8]) -> Result<Vec<u8>, SignError> {
        self.calls += 1;
        Ok(SigningKey::<Sha256>::new(self.key.clone())
            .sign(data)
            .to_vec())
    }
}

/// The test PKI's servers.
#[derive(Default)]
struct Pki {
    offline: bool,
    requests: Vec<String>,
}

impl Fetch for Pki {
    fn get(&mut self, url: &str) -> Result<Vec<u8>, String> {
        self.requests.push(url.to_owned());
        match url {
            _ if self.offline => Err("network unreachable".into()),
            "http://pki.test/ca.crl" => Ok(CA_CRL.to_vec()),
            "http://pki.test/root.crl" => Ok(ROOT_CRL.to_vec()),
            _ => Err("404".into()),
        }
    }

    fn post(&mut self, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>, String> {
        self.requests.push(url.to_owned());
        if self.offline || url != "http://ocsp.pki.test/" {
            return Err("network unreachable".into());
        }
        assert_eq!(content_type, "application/ocsp-request");
        openssl_ocsp(body).ok_or_else(|| "openssl not available".into())
    }
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ltv")
}

fn have_openssl() -> bool {
    Command::new("openssl").arg("version").output().is_ok()
}

/// Answers an OCSP request from the CA database with `openssl ocsp`.
fn openssl_ocsp(request: &[u8]) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join(format!(
        "gancho-ocsp-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("req.der"), request).unwrap();
    let f = fixtures();
    let out = Command::new("openssl")
        .arg("ocsp")
        .arg("-index")
        .arg(f.join("ca-index.txt"))
        .arg("-rsigner")
        .arg(f.join("ca.pem"))
        .arg("-rkey")
        .arg(f.join("ca-key.pem"))
        .arg("-CA")
        .arg(f.join("ca.pem"))
        .arg("-reqin")
        .arg(dir.join("req.der"))
        .arg("-respout")
        .arg(dir.join("resp.der"))
        .args(["-ndays", "36500"])
        .output()
        .ok()?;
    let resp = out
        .status
        .success()
        .then(|| std::fs::read(dir.join("resp.der")).ok())
        .flatten();
    let _ = std::fs::remove_dir_all(&dir);
    resp
}

fn save_for_inspection(name: &str, pdf: &[u8]) {
    if let Some(dir) = std::env::var_os("GANCHO_TEST_OUT") {
        std::fs::write(std::path::Path::new(&dir).join(name), pdf).unwrap();
    }
}

fn options(cert: &[u8]) -> SignOptions {
    SignOptions {
        chain: issuer_chain(cert, &[CA, ROOT]),
        ..Default::default()
    }
}

fn sign_lt(input: &[u8], cert: &'static [u8], key: &str, pki: &mut Pki) -> Vec<u8> {
    let mut signer = SoftSigner::new(cert, key);
    let (pdf, warnings) = sign_pdf_lt(input, &mut signer, &options(cert), None, pki).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    pdf
}

#[test]
fn long_term_signature_carries_revocation_data() {
    let mut pki = Pki::default();
    let pdf = sign_lt(SAMPLE, LEAF, LEAF_KEY, &mut pki);
    save_for_inspection("ltv.pdf", &pdf);

    let dss = gancho_core::ltv::read_dss(&Document::load_mem(&pdf).unwrap());
    assert!(dss.certs.contains(&LEAF.to_vec()));
    assert!(dss.certs.contains(&CA.to_vec()));
    assert!(dss.certs.contains(&ROOT.to_vec()));
    assert!(dss.crls.contains(&ROOT_CRL.to_vec()));

    let reports = verify_pdf(&pdf, &[ROOT], &[]).unwrap();
    assert_eq!(reports.len(), 1);
    let r = &reports[0];
    // The DSS goes in an update after the signature, which is fine.
    assert!(!r.covers_whole_file);
    assert!(r.changes_after.is_empty(), "{:?}", r.changes_after);
    assert!(r.is_valid());
    assert!(r.long_term());
    assert_eq!(r.revocation.len(), 2);
    let leaf = r.revocation[0].finding.unwrap();
    assert_eq!(leaf.status, Status::Good);
    if have_openssl() {
        assert_eq!(leaf.source, Source::Ocsp);
        assert_eq!(dss.ocsps.len(), 1);
    } else {
        assert_eq!(leaf.source, Source::Crl);
    }
    assert_eq!(r.revocation[1].finding.unwrap().source, Source::Crl);
}

#[test]
fn plain_signature_is_not_long_term() {
    let pdf = sign_pdf(SAMPLE, &mut SoftSigner::new(LEAF, LEAF_KEY), &options(LEAF)).unwrap();
    let r = &verify_pdf(&pdf, &[ROOT], &[]).unwrap()[0];
    assert!(r.is_valid());
    assert!(!r.long_term());
    assert!(r.revocation.iter().all(|r| r.finding.is_none()));
}

#[test]
fn crl_is_used_without_an_ocsp_server() {
    let mut pki = Pki::default();
    let pdf = sign_lt(SAMPLE, CRL_ONLY, CRL_ONLY_KEY, &mut pki);
    assert!(!pki.requests.iter().any(|u| u.contains("ocsp")));
    let r = &verify_pdf(&pdf, &[ROOT], &[]).unwrap()[0];
    assert!(r.long_term());
    assert_eq!(r.revocation[0].finding.unwrap().source, Source::Crl);
}

#[test]
fn revoked_certificate_is_not_used_to_sign() {
    let mut signer = SoftSigner::new(REVOKED, REVOKED_KEY);
    let err = sign_pdf_lt(
        SAMPLE,
        &mut signer,
        &options(REVOKED),
        None,
        &mut Pki::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, PdfError::Ltv(LtvError::Revoked { .. })),
        "{err}"
    );
    assert_eq!(signer.calls, 0);
}

#[test]
fn unreachable_ca_stops_before_signing() {
    let mut signer = SoftSigner::new(LEAF, LEAF_KEY);
    let mut pki = Pki {
        offline: true,
        ..Default::default()
    };
    let err = sign_pdf_lt(SAMPLE, &mut signer, &options(LEAF), None, &mut pki).unwrap_err();
    assert!(
        matches!(err, PdfError::Ltv(LtvError::Unavailable { .. })),
        "{err}"
    );
    assert_eq!(signer.calls, 0);
}

#[test]
fn stored_revocation_invalidates_the_signature() {
    // Signed without checking, then the CA's CRL (which lists it) is added.
    let pdf = sign_pdf(
        SAMPLE,
        &mut SoftSigner::new(REVOKED, REVOKED_KEY),
        &options(REVOKED),
    )
    .unwrap();
    let data = ValidationData {
        crls: vec![CA_CRL.to_vec()],
        ..Default::default()
    };
    let pdf = add_dss(&pdf, &data).unwrap();
    let r = &verify_pdf(&pdf, &[ROOT], &[]).unwrap()[0];
    assert!(r.revoked);
    assert!(!r.is_valid());
    assert!(matches!(
        r.revocation[0].finding.unwrap().status,
        Status::Revoked(_)
    ));
}

#[test]
fn validation_data_can_be_added_later() {
    let pdf = sign_pdf(SAMPLE, &mut SoftSigner::new(LEAF, LEAF_KEY), &options(LEAF)).unwrap();
    let (pdf, warnings) = add_validation_data(&pdf, &mut Pki::default()).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    let r = &verify_pdf(&pdf, &[ROOT], &[]).unwrap()[0];
    assert!(r.is_valid());
    assert!(r.long_term());
    // Nothing new to add the second time.
    let (again, _) = add_validation_data(&pdf, &mut Pki::default()).unwrap();
    assert_eq!(again, pdf);
}

#[test]
fn second_signer_keeps_the_first_valid() {
    let mut pki = Pki::default();
    let once = sign_lt(SAMPLE, LEAF, LEAF_KEY, &mut pki);
    let asked = pki.requests.len();
    let twice = sign_lt(&once, CRL_ONLY, CRL_ONLY_KEY, &mut pki);
    assert!(pki.requests.len() > asked);

    save_for_inspection("ltv-two-signers.pdf", &twice);
    let reports = verify_pdf(&twice, &[ROOT], &[]).unwrap();
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].field.as_deref(), Some("Firma"));
    assert_eq!(reports[1].field.as_deref(), Some("Firma2"));
    assert!(reports[0].signer.as_deref().unwrap().contains("leaf"));
    assert!(reports[1].signer.as_deref().unwrap().contains("crl-only"));
    for r in &reports {
        assert!(r.changes_after.is_empty(), "{:?}", r.changes_after);
        assert!(r.is_valid());
        assert!(r.long_term());
    }

    // A plain signature on top keeps both earlier ones valid too.
    let thrice = sign_pdf(&twice, &mut SoftSigner::new(LEAF, LEAF_KEY), &options(LEAF)).unwrap();
    let reports = verify_pdf(&thrice, &[ROOT], &[]).unwrap();
    assert_eq!(reports.len(), 3);
    assert!(reports.iter().all(|r| r.is_valid()));
}

#[test]
fn visible_second_signature_is_allowed() {
    let once = sign_pdf(SAMPLE, &mut SoftSigner::new(LEAF, LEAF_KEY), &options(LEAF)).unwrap();
    let visible = SignOptions {
        appearance: Some(Default::default()),
        ..options(CRL_ONLY)
    };
    let twice = sign_pdf(
        &once,
        &mut SoftSigner::new(CRL_ONLY, CRL_ONLY_KEY),
        &visible,
    )
    .unwrap();
    let reports = verify_pdf(&twice, &[ROOT], &[]).unwrap();
    assert!(
        reports[0].changes_after.is_empty(),
        "{:?}",
        reports[0].changes_after
    );
    assert!(reports.iter().all(|r| r.is_valid()));
}

#[test]
fn content_changed_after_signing_is_reported() {
    let signed = sign_pdf(SAMPLE, &mut SoftSigner::new(LEAF, LEAF_KEY), &options(LEAF)).unwrap();
    // Draw something new on the first page in a later revision.
    let doc = Document::load_mem(&signed).unwrap();
    let page = *doc.get_pages().get(&1).unwrap();
    let mut inc = IncrementalDocument::create_from(signed.clone(), doc);
    let extra = inc.new_document.add_object(Stream::new(
        Default::default(),
        b"BT /F1 24 Tf 100 100 Td (PAGADO) Tj ET".to_vec(),
    ));
    inc.opt_clone_object_to_new_document(page).unwrap();
    let page_dict = inc
        .new_document
        .get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap();
    let mut contents = match page_dict.get(b"Contents").unwrap().clone() {
        Object::Array(a) => a,
        other => vec![other],
    };
    contents.push(Object::Reference(extra));
    page_dict.set("Contents", Object::Array(contents));
    for key in [b"Index".as_slice(), b"DecodeParms", b"XRefStm", b"Filter"] {
        inc.new_document.trailer.remove(key);
    }
    let mut tampered = Vec::new();
    inc.save_to(&mut tampered).unwrap();

    let r = &verify_pdf(&tampered, &[ROOT], &[]).unwrap()[0];
    assert_eq!(r.integrity, Ok(()));
    assert!(!r.is_valid());
    assert!(
        r.changes_after.iter().any(|c| c.contains("a page")),
        "{:?}",
        r.changes_after
    );
}
