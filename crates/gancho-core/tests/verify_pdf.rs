//! Signs the sample PDF with a certificate issued by a test CA hierarchy
//! (root → intermediate → signer, like ACRN → Ministerio del Interior →
//! cédula) and checks what `verify_pdf` reports.

use gancho_core::ca::issuer_chain;
use gancho_core::pdf::{SignOptions, sign_pdf};
use gancho_core::verify::{IntegrityError, verify_pdf};
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

const FORGED: &[u8] = include_bytes!("fixtures/chain-forged.der");
const FORGED_KEY: &str = include_str!("fixtures/chain-forged-key.pem");

struct SoftSigner(RsaPrivateKey, &'static [u8]);

impl Signer for SoftSigner {
    fn certificate_der(&self) -> &[u8] {
        self.1
    }
    fn sign_sha256_rsa(&mut self, data: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(SigningKey::<Sha256>::new(self.0.clone())
            .sign(data)
            .to_vec())
    }
}

fn signer() -> SoftSigner {
    SoftSigner(RsaPrivateKey::from_pkcs8_pem(LEAF_KEY).unwrap(), LEAF)
}

fn sign(input: &[u8]) -> Vec<u8> {
    let options = SignOptions {
        reason: Some("Prueba".into()),
        chain: issuer_chain(LEAF, &[ROOT, INTERMEDIATE]),
        ..Default::default()
    };
    sign_pdf(input, &mut signer(), &options).unwrap()
}

#[test]
fn builds_chain_up_to_the_root() {
    assert_eq!(
        issuer_chain(LEAF, &[ROOT, INTERMEDIATE]),
        vec![INTERMEDIATE.to_vec(), ROOT.to_vec()]
    );
    // Without the intermediate there is no path at all.
    assert!(issuer_chain(LEAF, &[ROOT]).is_empty());
    assert!(issuer_chain(ROOT, &[ROOT, INTERMEDIATE]).is_empty());
}

#[test]
fn trusted_signature_verifies() {
    let signed = sign(SAMPLE);
    let reports = verify_pdf(&signed, &[ROOT], &[]).unwrap();
    assert_eq!(reports.len(), 1);
    let r = &reports[0];
    assert_eq!(r.integrity, Ok(()));
    assert!(r.covers_whole_file);
    assert!(r.trusted);
    assert_eq!(r.valid_at_signing_time, Some(true));
    assert!(r.is_valid());
    assert_eq!(r.field.as_deref(), Some("Firma"));
    assert_eq!(r.reason.as_deref(), Some("Prueba"));
    assert_eq!(r.sub_filter.as_deref(), Some("ETSI.CAdES.detached"));
    assert!(r.signer.as_deref().unwrap().contains("PRUEBA FIRMANTE"));
    assert_eq!(r.chain.len(), 2);
    assert!(r.chain[1].contains("PRUEBA RAIZ"));
}

#[test]
fn unknown_root_is_not_trusted() {
    let signed = sign(SAMPLE);
    let r = &verify_pdf(&signed, &[], &[]).unwrap()[0];
    assert_eq!(r.integrity, Ok(()));
    assert!(!r.trusted);
    assert!(!r.is_valid());
}

#[test]
fn tampering_is_detected() {
    let mut signed = sign(SAMPLE);
    let pos = signed
        .windows(19)
        .position(|w| w == b"Documento de prueba")
        .unwrap();
    signed[pos] = b'X';
    let r = &verify_pdf(&signed, &[ROOT], &[]).unwrap()[0];
    assert_eq!(r.integrity, Err(IntegrityError::Digest));
    assert!(!r.is_valid());
}

#[test]
fn second_signature_marks_the_first_as_partial() {
    let twice = sign(&sign(SAMPLE));
    let reports = verify_pdf(&twice, &[ROOT], &[]).unwrap();
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].field.as_deref(), Some("Firma"));
    assert_eq!(reports[1].field.as_deref(), Some("Firma2"));
    assert!(reports.iter().all(|r| r.integrity.is_ok() && r.trusted));
    assert!(!reports[0].covers_whole_file);
    assert!(reports[1].covers_whole_file);
}

/// A certificate "issued" by an ordinary signer (not a CA) must not chain,
/// or any cédula holder could sign in someone else's name.
#[test]
fn signer_cannot_act_as_a_ca() {
    assert!(issuer_chain(FORGED, &[LEAF, INTERMEDIATE, ROOT]).is_empty());
    let mut forger = SoftSigner(RsaPrivateKey::from_pkcs8_pem(FORGED_KEY).unwrap(), FORGED);
    let options = SignOptions {
        chain: vec![LEAF.to_vec(), INTERMEDIATE.to_vec(), ROOT.to_vec()],
        ..Default::default()
    };
    let signed = sign_pdf(SAMPLE, &mut forger, &options).unwrap();
    let r = &verify_pdf(&signed, &[ROOT], &[]).unwrap()[0];
    assert_eq!(r.integrity, Ok(()));
    assert!(!r.trusted);
}

#[test]
fn unsigned_pdf_has_no_signatures() {
    assert!(verify_pdf(SAMPLE, &[ROOT], &[]).unwrap().is_empty());
}

#[test]
fn save_chain_signed_sample() {
    if let Some(dir) = std::env::var_os("GANCHO_TEST_OUT") {
        std::fs::write(std::path::Path::new(&dir).join("chain.pdf"), sign(SAMPLE)).unwrap();
    }
}

#[test]
fn visible_signature_box() {
    use gancho_core::appearance::Appearance;
    let options = SignOptions {
        reason: Some("Conformidad".into()),
        location: Some("Montevideo".into()),
        chain: issuer_chain(LEAF, &[ROOT, INTERMEDIATE]),
        appearance: Some(Appearance::default()),
        ..Default::default()
    };
    let signed = sign_pdf(SAMPLE, &mut signer(), &options).unwrap();
    if let Some(dir) = std::env::var_os("GANCHO_TEST_OUT") {
        std::fs::write(std::path::Path::new(&dir).join("visible.pdf"), &signed).unwrap();
    }
    assert!(verify_pdf(&signed, &[ROOT], &[]).unwrap()[0].is_valid());

    let doc = lopdf::Document::load_mem(&signed).unwrap();
    let widget = doc
        .objects
        .values()
        .filter_map(|o| o.as_dict().ok())
        .find(|d| d.get(b"FT").and_then(|o| o.as_name()).ok() == Some(b"Sig"))
        .unwrap();
    let rect: Vec<f32> = widget
        .get(b"Rect")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o.as_float().unwrap())
        .collect();
    assert_eq!(rect, [36.0, 36.0, 256.0, 106.0]);
    let ap = widget
        .get(b"AP")
        .unwrap()
        .as_dict()
        .unwrap()
        .get(b"N")
        .unwrap()
        .as_reference()
        .unwrap();
    let stream = doc.get_object(ap).unwrap().as_stream().unwrap();
    let text = String::from_utf8_lossy(&stream.content);
    assert!(text.contains("PRUEBA FIRMANTE"), "{text}");
    assert!(text.contains("Motivo: Conformidad"));
}

/// Some signers (TuID, for one) write the CMS in BER with indefinite
/// lengths. Re-encode our own signature that way and check it still reads.
#[test]
fn ber_indefinite_length_signature_verifies() {
    let mut signed = sign(SAMPLE);
    // The hex string fills the gap the ByteRange leaves: `<` ... `>`.
    let br = signed.windows(10).position(|w| w == b"/ByteRange").unwrap();
    let nums: Vec<usize> = std::str::from_utf8(&signed[br + 10..br + 80])
        .unwrap()
        .split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty())
        .take(3)
        .map(|t| t.parse().unwrap())
        .collect();
    let (start, end) = (nums[1] + 1, nums[2] - 1);
    let hex = std::str::from_utf8(&signed[start..end]).unwrap();
    let der: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();

    // ContentInfo SEQUENCE { OID, [0] { SignedData } } with both outer
    // constructed elements switched to indefinite length.
    let (outer_hdr, outer_len) = header(&der);
    let body = &der[outer_hdr..outer_hdr + outer_len];
    let (oid_hdr, oid_len) = header(body);
    let oid = &body[..oid_hdr + oid_len];
    let explicit = &body[oid_hdr + oid_len..];
    let (exp_hdr, exp_len) = header(explicit);
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(oid);
    ber.extend_from_slice(&[0xA0, 0x80]);
    ber.extend_from_slice(&explicit[exp_hdr..exp_hdr + exp_len]);
    ber.extend_from_slice(&[0, 0, 0, 0]);

    let new_hex: String = ber.iter().map(|b| format!("{b:02X}")).collect();
    assert!(new_hex.len() <= end - start);
    signed[start..start + new_hex.len()].copy_from_slice(new_hex.as_bytes());
    for b in &mut signed[start + new_hex.len()..end] {
        *b = b'0';
    }
    let r = &verify_pdf(&signed, &[ROOT], &[]).unwrap()[0];
    assert_eq!(r.integrity, Ok(()));
    assert!(r.is_valid());
}

/// DER header length and content length.
fn header(b: &[u8]) -> (usize, usize) {
    match b[1] {
        n if n < 0x80 => (2, n as usize),
        0x81 => (3, b[2] as usize),
        0x82 => (4, u16::from_be_bytes([b[2], b[3]]) as usize),
        _ => panic!("unexpected length"),
    }
}
