//! Signs generated PDFs with a software key and checks the result the way a
//! validator would: byte range, message digest, signature, and structure.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};
use gancho_core::pdf::{SignOptions, sign_pdf};
use gancho_core::{SignError, Signer};
use lopdf::{Document, Object, SaveOptions, Stream, dictionary};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer as _, Verifier};
use sha2::{Digest, Sha256};

const CERT: &[u8] = include_bytes!("fixtures/test-cert.der");
const KEY: &str = include_str!("fixtures/test-key.pem");

struct SoftSigner(RsaPrivateKey);

impl Signer for SoftSigner {
    fn certificate_der(&self) -> &[u8] {
        CERT
    }
    fn sign_sha256_rsa(&mut self, data: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(SigningKey::<Sha256>::new(self.0.clone())
            .sign(data)
            .to_vec())
    }
}

fn signer() -> SoftSigner {
    SoftSigner(RsaPrivateKey::from_pkcs8_pem(KEY).unwrap())
}

/// A one-page PDF; `modern` writes it with object and xref streams.
fn sample_pdf(modern: bool, with_form: bool) -> Vec<u8> {
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let font_id = doc.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let content = doc.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 24 Tf 72 720 Td (Hola, gancho) Tj ET".to_vec(),
    ));
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Contents" => content,
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
    });
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
        }),
    );
    let mut catalog = dictionary! { "Type" => "Catalog", "Pages" => pages_id };
    if with_form {
        let form = doc.add_object(dictionary! { "Fields" => Vec::<Object>::new() });
        catalog.set("AcroForm", form);
    }
    let catalog_id = doc.add_object(catalog);
    doc.trailer.set("Root", catalog_id);
    let mut out = Vec::new();
    if modern {
        doc.save_with_options(
            &mut out,
            SaveOptions::builder().use_object_streams(true).build(),
        )
        .unwrap();
    } else {
        doc.save_to(&mut out).unwrap();
    }
    out
}

/// Validates the single (last) signature in `pdf` and returns its field.
fn check_signature(original: &[u8], pdf: &[u8]) {
    assert!(
        pdf.starts_with(original),
        "incremental update must keep the original bytes"
    );

    let doc = Document::load_mem(pdf).expect("signed PDF parses");
    let root = doc.catalog().unwrap();
    let (_, form) = doc.dereference(root.get(b"AcroForm").unwrap()).unwrap();
    let form = form.as_dict().unwrap();
    assert_eq!(form.get(b"SigFlags").unwrap().as_i64().unwrap(), 3);
    let (_, fields) = doc.dereference(form.get(b"Fields").unwrap()).unwrap();
    let field_ref = fields
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .as_reference()
        .unwrap();
    let field = doc.get_dictionary(field_ref).unwrap();
    assert_eq!(field.get(b"FT").unwrap().as_name().unwrap(), b"Sig");
    let sig = doc
        .get_dictionary(field.get(b"V").unwrap().as_reference().unwrap())
        .unwrap();
    assert_eq!(
        sig.get(b"SubFilter").unwrap().as_name().unwrap(),
        b"ETSI.CAdES.detached"
    );

    let range: Vec<usize> = sig
        .get(b"ByteRange")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o.as_i64().unwrap() as usize)
        .collect();
    assert_eq!(range[0], 0);
    assert_eq!(
        range[2] + range[3],
        pdf.len(),
        "byte range must cover the file to the end"
    );
    assert_eq!(pdf[range[1]], b'<');
    assert_eq!(pdf[range[2] - 1], b'>');

    let mut h = Sha256::new();
    h.update(&pdf[..range[1]]);
    h.update(&pdf[range[2]..range[2] + range[3]]);
    let digest = h.finalize();

    let cms_bytes = match sig.get(b"Contents").unwrap() {
        Object::String(b, _) => b.clone(),
        _ => panic!("Contents is not a string"),
    };
    let ci = ContentInfo::from_der(trim_der(&cms_bytes)).unwrap();
    let sd: SignedData = ci.content.decode_as().unwrap();
    let si = sd.signer_infos.0.iter().next().unwrap();
    let attrs = si.signed_attrs.as_ref().unwrap();
    let md = attrs
        .iter()
        .find(|a| a.oid.to_string() == "1.2.840.113549.1.9.4")
        .unwrap();
    let md: der::asn1::OctetString = md.values.iter().next().unwrap().decode_as().unwrap();
    assert_eq!(
        md.as_bytes(),
        digest.as_slice(),
        "messageDigest matches the byte range"
    );
    assert!(
        attrs
            .iter()
            .any(|a| a.oid.to_string() == "1.2.840.113549.1.9.16.2.47")
    );
    assert!(
        !attrs
            .iter()
            .any(|a| a.oid.to_string() == "1.2.840.113549.1.9.5"),
        "no signing-time"
    );

    let key = RsaPrivateKey::from_pkcs8_pem(KEY).unwrap().to_public_key();
    VerifyingKey::<Sha256>::new(key)
        .verify(
            &attrs.to_der().unwrap(),
            &Signature::try_from(si.signature.as_bytes()).unwrap(),
        )
        .expect("RSA signature over the signed attributes verifies");
}

/// `/Contents` is zero-padded after the DER; cut to the DER's own length.
fn trim_der(b: &[u8]) -> &[u8] {
    let len = match b[1] {
        n if n < 0x80 => 2 + n as usize,
        0x81 => 3 + b[2] as usize,
        0x82 => 4 + u16::from_be_bytes([b[2], b[3]]) as usize,
        _ => panic!("unexpected length"),
    };
    &b[..len]
}

fn save_for_inspection(name: &str, pdf: &[u8]) {
    if let Some(dir) = std::env::var_os("GANCHO_TEST_OUT") {
        std::fs::write(std::path::Path::new(&dir).join(name), pdf).unwrap();
    }
}

#[test]
fn signs_classic_xref_pdf() {
    let original = sample_pdf(false, false);
    let signed = sign_pdf(&original, &mut signer(), &SignOptions::default()).unwrap();
    check_signature(&original, &signed);
    save_for_inspection("classic.pdf", &signed);
}

#[test]
fn signs_xref_stream_pdf() {
    let original = sample_pdf(true, false);
    let signed = sign_pdf(&original, &mut signer(), &SignOptions::default()).unwrap();
    check_signature(&original, &signed);
    save_for_inspection("modern.pdf", &signed);
}

#[test]
fn signs_pdf_with_existing_acroform() {
    let original = sample_pdf(false, true);
    let options = SignOptions {
        reason: Some("Conformidad".into()),
        location: Some("Montevideo".into()),
        ..Default::default()
    };
    let signed = sign_pdf(&original, &mut signer(), &options).unwrap();
    check_signature(&original, &signed);
    save_for_inspection("form.pdf", &signed);
}

#[test]
fn second_signature_keeps_the_first_valid() {
    let original = sample_pdf(false, false);
    let once = sign_pdf(&original, &mut signer(), &SignOptions::default()).unwrap();
    let twice = sign_pdf(&once, &mut signer(), &SignOptions::default()).unwrap();
    check_signature(&once, &twice);
    let doc = Document::load_mem(&twice).unwrap();
    let (_, form) = doc
        .dereference(doc.catalog().unwrap().get(b"AcroForm").unwrap())
        .unwrap();
    let (_, fields) = doc
        .dereference(form.as_dict().unwrap().get(b"Fields").unwrap())
        .unwrap();
    assert_eq!(fields.as_array().unwrap().len(), 2);
    save_for_inspection("twice.pdf", &twice);
    let _ = CERT.to_vec().len();
}
