//! Checking the signatures in a PDF.
//!
//! For each signature this checks that the signed bytes are intact (the
//! `/ByteRange` digest matches the CMS `message-digest`, and the CMS
//! signature verifies with the signer's certificate), whether later
//! revisions were appended after it, whether the signer's certificate
//! chains up to a trusted root, and any RFC 3161 signature timestamp.
//! With several signatures, the revisions appended after each one are
//! checked to only add signatures and validation data. Revocation is
//! checked against the data stored in the PDF (its DSS) for long-term
//! validation; nothing is fetched from the network.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use der::asn1::OctetString;
use der::{Decode, Encode};
use lopdf::{Dictionary, Document, Object, ObjectId};
use x509_cert::Certificate;
use x509_tsp::TstInfo;

use crate::ber;
use crate::ca::{self, Hash};
use crate::changes;
use crate::ltv::{ValidationData, read_dss};
use crate::revocation::{self, Finding, Status};

const ID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const ID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const ID_SIGNATURE_TIME_STAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("could not read the PDF: {0}")]
    Parse(lopdf::Error),
}

/// Why a signature's (or timestamp's) bytes don't check out.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntegrityError {
    #[error("/ByteRange is missing or malformed")]
    ByteRange,
    #[error("/ByteRange does not frame the /Contents hole")]
    ByteRangeGap,
    #[error("the signature is not readable CMS: {0}")]
    Cms(String),
    #[error("unsupported algorithm {0}")]
    Algorithm(String),
    #[error("the signer's certificate is not in the signature")]
    SignerCertificate,
    #[error("the signed data was changed: the digest does not match")]
    Digest,
    #[error("the cryptographic signature does not verify")]
    Signature,
    #[error("the timestamp is for a different signature")]
    TimestampImprint,
}

/// An RFC 3161 timestamp on a signature (PAdES-B-T).
#[derive(Debug, Clone)]
pub struct TimestampReport {
    /// Time asserted by the timestamp authority, Unix seconds.
    pub time: Option<i64>,
    /// Timestamp authority certificate subject.
    pub tsa: Option<String>,
    /// The token is intact, signed by the TSA, and covers this signature.
    pub integrity: Result<(), IntegrityError>,
    /// The TSA certificate chains to a trust anchor.
    pub trusted: bool,
}

impl TimestampReport {
    /// The time, when the token is intact and its authority trusted.
    pub fn trusted_time(&self) -> Option<i64> {
        (self.integrity.is_ok() && self.trusted)
            .then_some(self.time)
            .flatten()
    }
}

/// One signature found in the PDF.
#[derive(Debug, Clone)]
pub struct SignatureReport {
    /// Form field name, e.g. "Firma".
    pub field: Option<String>,
    /// `/SubFilter`, e.g. "ETSI.CAdES.detached".
    pub sub_filter: Option<String>,
    /// Claimed signing time from `/M`, as written in the PDF.
    pub signed_at: Option<String>,
    pub reason: Option<String>,
    pub location: Option<String>,
    /// Signer certificate subject, when it could be found.
    pub signer: Option<String>,
    /// Whether the signed bytes and the cryptographic signature check out.
    pub integrity: Result<(), IntegrityError>,
    /// False when the file has later revisions appended after this
    /// signature (for example, another signature).
    pub covers_whole_file: bool,
    /// Subjects from the signer's issuer up to the top of the path found.
    pub chain: Vec<String>,
    /// The path ends at one of the trust anchors.
    pub trusted: bool,
    /// Every certificate on the path was valid at the signing time: the
    /// timestamp's when it is trusted, otherwise the claimed `/M` time
    /// (`None` when neither is available).
    pub valid_at_signing_time: Option<bool>,
    pub timestamp: Option<TimestampReport>,
    /// Revocation status from the PDF's validation data for the signer's
    /// certificate and each CA above it (not the root), signer first.
    pub revocation: Vec<RevocationReport>,
    /// A certificate on the path was revoked before the signature was
    /// made (or, without a trusted timestamp, at all).
    pub revoked: bool,
    /// What later revisions changed beyond adding signatures and
    /// validation data; empty when nothing else changed.
    pub changes_after: Vec<String>,
}

/// What the stored validation data says about one certificate.
#[derive(Debug, Clone)]
pub struct RevocationReport {
    pub subject: String,
    /// `None` when the PDF holds nothing about this certificate.
    pub finding: Option<Finding>,
}

impl SignatureReport {
    /// Intact, trusted, in date and not revoked, with an intact timestamp
    /// if it has one, and no changes after it other than signatures.
    pub fn is_valid(&self) -> bool {
        self.integrity.is_ok()
            && self.trusted
            && self.valid_at_signing_time != Some(false)
            && self.timestamp.as_ref().is_none_or(|t| t.integrity.is_ok())
            && !self.revoked
            && self.changes_after.is_empty()
    }

    /// The PDF carries revocation data showing every certificate on the
    /// path was good, so the signature can be checked long-term.
    pub fn long_term(&self) -> bool {
        self.integrity.is_ok()
            && self.trusted
            && !self.revocation.is_empty()
            && self
                .revocation
                .iter()
                .all(|r| r.finding.is_some_and(|f| f.status == Status::Good))
    }
}

/// Finds and checks every signature in `pdf`. `anchors` are trusted root
/// certificates and `intermediates` extra CA certificates to build paths
/// with (both DER); the bundled national CAs are added automatically.
/// Timestamps are also accepted from authorities under the public roots
/// that browsers trust (Mozilla's list), since commercial TSAs such as
/// DigiCert chain there rather than to Uruguay's root.
pub fn verify_pdf(
    pdf: &[u8],
    anchors: &[&[u8]],
    intermediates: &[&[u8]],
) -> Result<Vec<SignatureReport>, VerifyError> {
    let doc = Document::load_mem(pdf).map_err(VerifyError::Parse)?;
    let names = field_names(&doc);
    let dss = read_dss(&doc);
    let mut anchors: Vec<&[u8]> = anchors.to_vec();
    anchors.extend(ca::bundled_roots());
    let mut intermediates: Vec<&[u8]> = intermediates.to_vec();
    intermediates.extend(ca::BUNDLED);
    intermediates.extend(dss.certs.iter().map(Vec::as_slice));
    let trust = Trust {
        anchors: &anchors,
        intermediates: &intermediates,
    };
    let tsa_anchors: Vec<&[u8]> = anchors
        .iter()
        .copied()
        .chain(
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|c| c.as_ref()),
        )
        .collect();
    let tsa_trust = Trust {
        anchors: &tsa_anchors,
        intermediates: &intermediates,
    };

    let ctx = Context {
        pdf,
        doc: &doc,
        dss: &dss,
        trust,
        tsa_trust,
    };
    Ok(signature_dicts(&doc)
        .into_iter()
        .map(|(id, d)| check_one(&ctx, d, names.get(&id).cloned()))
        .collect())
}

/// Signature dictionaries in the order they were made (by where their
/// signed range ends).
fn signature_dicts(doc: &Document) -> Vec<(ObjectId, &Dictionary)> {
    let mut sigs: Vec<(ObjectId, &Dictionary)> = doc
        .objects
        .iter()
        .filter_map(|(id, obj)| Some((*id, obj.as_dict().ok()?)))
        .filter(|(_, d)| d.has(b"ByteRange") && d.has(b"Contents"))
        .collect();
    sigs.sort_by_key(|(_, d)| byte_range(d).map(|r| r[2] + r[3]).unwrap_or(0));
    sigs
}

/// The certificates behind one signature, for collecting validation data.
pub(crate) struct SignatureCertificates {
    pub signer: Vec<u8>,
    /// Every certificate the signature carries.
    pub carried: Vec<Vec<u8>>,
    /// The timestamp authority's certificate and those its token carries.
    pub timestamp: Option<(Vec<u8>, Vec<Vec<u8>>)>,
}

/// The certificates of every signature in `pdf` that can be read, without
/// checking the signatures.
pub(crate) fn signature_certificates(pdf: &[u8]) -> Vec<SignatureCertificates> {
    let Ok(doc) = Document::load_mem(pdf) else {
        return Vec::new();
    };
    signature_dicts(&doc)
        .into_iter()
        .filter_map(|(_, d)| {
            let sd = parse_signed_data(d.get(b"Contents").ok()?.as_str().ok()?).ok()?;
            let (signer, carried) = signer_certificate(&sd)?;
            let timestamp = timestamp_token(sd.signer_infos.0.iter().next()?)
                .and_then(|t| parse_signed_data(&t).ok())
                .and_then(|t| signer_certificate(&t));
            Some(SignatureCertificates {
                signer,
                carried,
                timestamp,
            })
        })
        .collect()
}

/// The first signer's certificate in `sd` and all the certificates it
/// carries, DER.
fn signer_certificate(sd: &SignedData) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
    let si = sd.signer_infos.0.iter().next()?;
    let certs = carried_certificates(sd);
    let signer = certs
        .iter()
        .find(|c| identifies(&si.sid, c))?
        .to_der()
        .ok()?;
    Some((
        signer,
        certs.iter().filter_map(|c| c.to_der().ok()).collect(),
    ))
}

struct Context<'a> {
    pdf: &'a [u8],
    doc: &'a Document,
    dss: &'a ValidationData,
    trust: Trust<'a>,
    tsa_trust: Trust<'a>,
}

struct Trust<'a> {
    anchors: &'a [&'a [u8]],
    intermediates: &'a [&'a [u8]],
}

impl Trust<'_> {
    /// The path from `cert` upwards (starting with `cert`) using `carried`
    /// certificates as well, and whether it ends at an anchor.
    fn path(&self, cert: &Certificate, carried: &[Vec<u8>]) -> (Vec<Certificate>, bool) {
        let der = cert.to_der().unwrap_or_default();
        let mut pool: Vec<&[u8]> = carried.iter().map(Vec::as_slice).collect();
        pool.extend(self.anchors);
        pool.extend(self.intermediates);
        let chain = ca::issuer_chain(&der, &pool);
        let trusted = self
            .anchors
            .contains(&chain.last().unwrap_or(&der).as_slice());
        let certs = std::iter::once(cert.clone())
            .chain(chain.iter().filter_map(|d| Certificate::from_der(d).ok()))
            .collect();
        (certs, trusted)
    }
}

fn check_one(ctx: &Context, sig: &Dictionary, field: Option<String>) -> SignatureReport {
    let pdf = ctx.pdf;
    let string = |key: &[u8]| {
        sig.get(key)
            .ok()
            .and_then(|o| o.as_str().ok())
            .map(decode_text)
    };
    let signed_at = string(b"M");
    let mut report = SignatureReport {
        field,
        sub_filter: sig
            .get(b"SubFilter")
            .and_then(Object::as_name)
            .ok()
            .map(|n| String::from_utf8_lossy(n).into_owned()),
        signed_at: signed_at.clone(),
        reason: string(b"Reason"),
        location: string(b"Location"),
        signer: None,
        integrity: Ok(()),
        covers_whole_file: false,
        chain: Vec::new(),
        trusted: false,
        valid_at_signing_time: None,
        timestamp: None,
        revocation: Vec::new(),
        revoked: false,
        changes_after: Vec::new(),
    };

    let Some(range) = byte_range(sig) else {
        report.integrity = Err(IntegrityError::ByteRange);
        return report;
    };
    let [a, b, c, d] = range;
    if a != 0 || b >= c || c + d > pdf.len() || pdf[b] != b'<' || pdf[c - 1] != b'>' {
        report.integrity = Err(IntegrityError::ByteRangeGap);
        return report;
    }
    report.covers_whole_file = pdf[c + d..].iter().all(u8::is_ascii_whitespace);
    if !report.covers_whole_file {
        report.changes_after = match Document::load_mem(&pdf[..c + d]) {
            Ok(signed) => changes::after(&signed, ctx.doc),
            Err(_) => vec!["the signed revision cannot be read on its own".into()],
        };
        if changes::docmdp_permissions(ctx.doc, sig) == Some(1) {
            report.changes_after.insert(
                0,
                "the document was certified with no changes allowed, yet it was changed".into(),
            );
        }
    }

    let Ok(contents) = sig.get(b"Contents").and_then(Object::as_str) else {
        report.integrity = Err(IntegrityError::ByteRange);
        return report;
    };
    let checked = parse_signed_data(contents)
        .and_then(|sd| check_signed_data(&sd, &[&pdf[..b], &pdf[c..c + d]]));
    let checked = match checked {
        Ok(c) => c,
        Err(e) => {
            report.integrity = Err(e);
            return report;
        }
    };

    report.signer = Some(checked.signer.tbs_certificate.subject.to_string());
    let (path, trusted) = ctx.trust.path(&checked.signer, &checked.certs);
    report.trusted = trusted;
    report.chain = path[1..]
        .iter()
        .map(|c| c.tbs_certificate.subject.to_string())
        .collect();
    report.timestamp = signature_timestamp(&checked.signer_info, &ctx.tsa_trust);
    let proven_time = report
        .timestamp
        .as_ref()
        .and_then(TimestampReport::trusted_time);
    let time = proven_time.or_else(|| signed_at.as_deref().and_then(parse_pdf_date));
    report.valid_at_signing_time = time.map(|t| path.iter().all(|c| valid_at(c, t)));
    report.revocation = path
        .windows(2)
        .map(|pair| RevocationReport {
            subject: pair[0].tbs_certificate.subject.to_string(),
            finding: revocation::check(&pair[0], &pair[1], &ctx.dss.ocsps, &ctx.dss.crls),
        })
        .collect();
    // Without a trusted timestamp the claimed time proves nothing, so any
    // revocation counts.
    report.revoked = report.revocation.iter().any(|r| match r.finding {
        Some(Finding {
            status: Status::Revoked(at),
            ..
        }) => proven_time.is_none_or(|t| at <= t),
        _ => false,
    });
    report
}

/// Checks the `signature-time-stamp` unsigned attribute, if present.
fn signature_timestamp(si: &SignerInfo, trust: &Trust) -> Option<TimestampReport> {
    let token = timestamp_token(si)?;
    let mut report = TimestampReport {
        time: None,
        tsa: None,
        integrity: Ok(()),
        trusted: false,
    };
    let result = (|| {
        let sd = parse_signed_data(&token)?;
        let tst_der = sd
            .encap_content_info
            .econtent
            .as_ref()
            .ok_or(IntegrityError::Cms("timestamp has no content".into()))?
            .decode_as::<OctetString>()
            .map_err(|e| IntegrityError::Cms(e.to_string()))?;
        let checked = check_signed_data(&sd, &[tst_der.as_bytes()])?;
        let tst = TstInfo::from_der(tst_der.as_bytes())
            .map_err(|e| IntegrityError::Cms(e.to_string()))?;
        report.time = Some(tst.gen_time.to_unix_duration().as_secs() as i64);
        report.tsa = Some(checked.signer.tbs_certificate.subject.to_string());
        let alg = tst.message_imprint.hash_algorithm.oid.to_string();
        let hash = Hash::from_digest_oid(&alg).ok_or(IntegrityError::Algorithm(alg))?;
        if hash.digest(&[si.signature.as_bytes()]) != tst.message_imprint.hashed_message.as_bytes()
        {
            return Err(IntegrityError::TimestampImprint);
        }
        report.trusted = trust.path(&checked.signer, &checked.certs).1;
        Ok(())
    })();
    report.integrity = result;
    Some(report)
}

/// The DER of the `signature-time-stamp` unsigned attribute's token.
fn timestamp_token(si: &SignerInfo) -> Option<Vec<u8>> {
    si.unsigned_attrs
        .as_ref()?
        .iter()
        .find(|a| a.oid.to_string() == ID_SIGNATURE_TIME_STAMP_TOKEN)?
        .values
        .iter()
        .next()?
        .to_der()
        .ok()
}

fn carried_certificates(sd: &SignedData) -> Vec<Certificate> {
    sd.certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|c| match c {
            CertificateChoices::Certificate(c) => Some(c.clone()),
            _ => None,
        })
        .collect()
}

fn identifies(sid: &SignerIdentifier, c: &Certificate) -> bool {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            c.tbs_certificate.issuer == ias.issuer
                && c.tbs_certificate.serial_number == ias.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(_) => false,
    }
}

fn parse_signed_data(der: &[u8]) -> Result<SignedData, IntegrityError> {
    let cms_err = |e: der::Error| IntegrityError::Cms(e.to_string());
    let der = ber::to_der(der).ok_or(IntegrityError::Cms("malformed encoding".into()))?;
    ContentInfo::from_der(&der)
        .map_err(cms_err)?
        .content
        .decode_as()
        .map_err(cms_err)
}

struct Checked {
    signer: Certificate,
    signer_info: SignerInfo,
    /// All certificates carried in the `SignedData`, DER.
    certs: Vec<Vec<u8>>,
}

/// Checks the first signer of `sd` against `content` (the signed bytes,
/// possibly in several pieces).
fn check_signed_data(sd: &SignedData, content: &[&[u8]]) -> Result<Checked, IntegrityError> {
    let cms_err = |e: der::Error| IntegrityError::Cms(e.to_string());
    let si = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or(IntegrityError::Cms("no signer".into()))?;
    let digest_alg = si.digest_alg.oid.to_string();
    let hash = Hash::from_digest_oid(&digest_alg).ok_or(IntegrityError::Algorithm(digest_alg))?;

    let certs = carried_certificates(sd);
    let signer = certs
        .iter()
        .find(|c| identifies(&si.sid, c))
        .ok_or(IntegrityError::SignerCertificate)?
        .clone();

    let attrs = si
        .signed_attrs
        .as_ref()
        .ok_or(IntegrityError::Cms("no signed attributes".into()))?;
    let message_digest = attrs
        .iter()
        .find(|a| a.oid.to_string() == ID_MESSAGE_DIGEST)
        .and_then(|a| a.values.iter().next())
        .and_then(|v| v.decode_as::<OctetString>().ok())
        .ok_or(IntegrityError::Cms("no message-digest".into()))?;
    if message_digest.as_bytes() != hash.digest(content) {
        return Err(IntegrityError::Digest);
    }

    let sig_alg = si.signature_algorithm.oid.to_string();
    let sig_hash = if sig_alg == ID_RSA_ENCRYPTION {
        hash
    } else {
        Hash::from_rsa_signature_oid(&sig_alg).ok_or(IntegrityError::Algorithm(sig_alg))?
    };
    let key = ca::public_key(&signer).map_err(|_| IntegrityError::Signature)?;
    let signed = attrs.to_der().map_err(cms_err)?;
    if !ca::verify_rsa(sig_hash, &key, &signed, si.signature.as_bytes()) {
        return Err(IntegrityError::Signature);
    }
    Ok(Checked {
        signer,
        signer_info: si.clone(),
        certs: certs.iter().filter_map(|c| c.to_der().ok()).collect(),
    })
}

/// `[offset1, length1, offset2, length2]`.
fn byte_range(sig: &Dictionary) -> Option<[usize; 4]> {
    let arr = sig.get(b"ByteRange").ok()?.as_array().ok()?;
    if arr.len() != 4 {
        return None;
    }
    let mut out = [0usize; 4];
    for (o, v) in out.iter_mut().zip(arr) {
        *o = usize::try_from(v.as_i64().ok()?).ok()?;
    }
    Some(out)
}

/// Maps signature dictionary ids to the names of the fields holding them.
fn field_names(doc: &Document) -> std::collections::HashMap<ObjectId, String> {
    doc.objects
        .values()
        .filter_map(|o| o.as_dict().ok())
        .filter_map(|d| {
            let v = d.get(b"V").ok()?.as_reference().ok()?;
            let t = d.get(b"T").ok()?.as_str().ok()?;
            Some((v, decode_text(t)))
        })
        .collect()
}

/// PDF text string: UTF-16BE with BOM, otherwise (close enough) Latin-1.
fn decode_text(b: &[u8]) -> String {
    if let Some(rest) = b.strip_prefix(&[0xFE, 0xFF]) {
        let units: Vec<u16> = rest
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        b.iter().map(|&c| c as char).collect()
    }
}

fn valid_at(cert: &Certificate, unix: i64) -> bool {
    let v = &cert.tbs_certificate.validity;
    let secs = |t: x509_cert::time::Time| t.to_unix_duration().as_secs() as i64;
    secs(v.not_before) <= unix && unix <= secs(v.not_after)
}

/// Parses `D:YYYYMMDDHHmmSS` with an optional `Z` or `+hh'mm'` offset into
/// Unix seconds. Missing trailing fields default as the PDF spec says.
pub fn parse_pdf_date(s: &str) -> Option<i64> {
    let s = s.strip_prefix("D:").unwrap_or(s);
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.len() < 4 {
        return None;
    }
    let field = |from: usize, len: usize, default: i64| -> Option<i64> {
        match digits.get(from..from + len) {
            Some(f) => f.parse().ok(),
            None => Some(default),
        }
    };
    let (y, mo, d) = (field(0, 4, 0)?, field(4, 2, 1)?, field(6, 2, 1)?);
    let (h, mi, se) = (field(8, 2, 0)?, field(10, 2, 0)?, field(12, 2, 0)?);
    let mut offset = 0;
    let rest = &s[digits.len()..];
    if let Some(sign @ ('+' | '-')) = rest.chars().next() {
        let nums: Vec<i64> = rest[1..]
            .split('\'')
            .filter(|p| !p.is_empty())
            .filter_map(|p| p.parse().ok())
            .collect();
        let mins = nums.first().copied().unwrap_or(0) * 60 + nums.get(1).copied().unwrap_or(0);
        offset = if sign == '+' { mins * 60 } else { -mins * 60 };
    }
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se - offset)
}

/// Unix seconds as `2026-10-27 21:11:31 UTC`.
pub fn format_utc(unix: i64) -> String {
    let (y, m, d) = crate::pdf::civil_from_days(unix.div_euclid(86_400));
    let s = unix.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        s / 3600,
        s / 60 % 60,
        s % 60
    )
}

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::{format_utc, parse_pdf_date};

    #[test]
    fn pdf_dates() {
        assert_eq!(parse_pdf_date("D:20261025120405Z"), Some(1_792_929_845));
        assert_eq!(
            parse_pdf_date("D:20261025090405-03'00'"),
            Some(1_792_929_845)
        );
        assert_eq!(parse_pdf_date("D:2026"), Some(1_767_225_600));
        assert_eq!(parse_pdf_date("nonsense"), None);
        assert_eq!(format_utc(1_792_929_845), "2026-10-25 12:04:05 UTC");
    }
}
