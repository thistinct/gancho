//! PAdES baseline B-B signing of PDF files.
//!
//! The signature is appended as an incremental update, so the original bytes
//! stay untouched and any earlier signatures remain valid. The update adds a
//! signature dictionary (`/SubFilter /ETSI.CAdES.detached`), an invisible
//! signature widget on the first page, and registers it in the AcroForm.
//!
//! The signed bytes are the whole file except the `/Contents` hex string,
//! as described by `/ByteRange`; the CMS signature then goes into that hole.

use std::time::{SystemTime, UNIX_EPOCH};

use lopdf::{Dictionary, Document, IncrementalDocument, Object, ObjectId, StringFormat};
use sha2::{Digest, Sha256};

use crate::Signer;
use crate::appearance::{self, Appearance};
use crate::ca;
use crate::cms::{CmsError, signed_data_detached};
use crate::ltv::{Collector, LtvError, add_dss};
use crate::revocation::Fetch;
use crate::tsp::TimestampAuthority;

/// Bytes reserved for the DER signature. A cédula signature with its
/// certificate and the CA chain is about 5 KiB, and public TSAs' tokens
/// (with their own certificate chains) add up to 8 KiB more.
const SIGNATURE_CAPACITY: usize = 24 * 1024;
/// Placeholder that is wide enough for any real offset, and is overwritten
/// in place once the final offsets are known.
const BYTE_RANGE_PLACEHOLDER: i64 = 9_999_999_999;

#[derive(Debug, thiserror::Error)]
pub enum PdfError {
    #[error("could not read the PDF: {0}")]
    Parse(lopdf::Error),
    #[error("encrypted PDFs are not supported yet")]
    Encrypted,
    #[error("the PDF has no pages")]
    NoPages,
    #[error("page {0} does not exist; the PDF has {1}")]
    Page(u32, u32),
    #[error("unexpected PDF structure: {0}")]
    Structure(lopdf::Error),
    #[error("could not write the signed PDF: {0}")]
    Write(std::io::Error),
    #[error("signature placeholder not found in the output")]
    Placeholder,
    #[error("the signature is {0} bytes, more than the {SIGNATURE_CAPACITY} reserved")]
    TooLarge(usize),
    #[error(
        "the document was certified by its author with no changes allowed, so it cannot be signed again"
    )]
    Certified,
    #[error(transparent)]
    Cms(#[from] CmsError),
    #[error(transparent)]
    Ltv(#[from] LtvError),
}

/// What to record in the signature dictionary.
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    /// `/Reason`, e.g. "Conformidad".
    pub reason: Option<String>,
    /// `/Location`, e.g. "Montevideo".
    pub location: Option<String>,
    /// Signing time; defaults to now.
    pub time: Option<SystemTime>,
    /// Extra certificates (DER) to embed, typically the issuing CA chain.
    pub chain: Vec<Vec<u8>>,
    /// Draw a visible signature box; otherwise the signature is invisible.
    pub appearance: Option<Appearance>,
}

/// Signs `input` and returns the signed PDF (PAdES-B-B).
pub fn sign_pdf(
    input: &[u8],
    signer: &mut dyn Signer,
    options: &SignOptions,
) -> Result<Vec<u8>, PdfError> {
    sign_pdf_timestamped(input, signer, options, None)
}

/// Like [`sign_pdf`], and with a `tsa` also timestamps the signature
/// (PAdES-B-T).
pub fn sign_pdf_timestamped(
    input: &[u8],
    signer: &mut dyn Signer,
    options: &SignOptions,
    tsa: Option<&mut dyn TimestampAuthority>,
) -> Result<Vec<u8>, PdfError> {
    let doc = Document::load_mem(input).map_err(PdfError::Parse)?;
    if doc.is_encrypted() {
        return Err(PdfError::Encrypted);
    }
    if crate::changes::forbids_changes(&doc) {
        return Err(PdfError::Certified);
    }
    let mut inc = IncrementalDocument::create_from(input.to_vec(), doc);
    let time = options.time.unwrap_or_else(SystemTime::now);
    let cert = signer.certificate_der().to_vec();
    add_signature_objects(&mut inc, options, time, &cert)?;

    let mut out = Vec::with_capacity(input.len() + 2 * SIGNATURE_CAPACITY + 4096);
    inc.save_to(&mut out).map_err(PdfError::Write)?;

    let (contents_start, contents_end) = fill_byte_range(&mut out, input.len())?;
    let mut hasher = Sha256::new();
    hasher.update(&out[..contents_start]);
    hasher.update(&out[contents_end..]);
    let digest: [u8; 32] = hasher.finalize().into();

    let cms = signed_data_detached(signer, &digest, &options.chain, tsa)?;
    if cms.len() > SIGNATURE_CAPACITY {
        return Err(PdfError::TooLarge(cms.len()));
    }
    let hex = hex_upper(&cms);
    out[contents_start + 1..contents_start + 1 + hex.len()].copy_from_slice(hex.as_bytes());
    Ok(out)
}

/// Like [`sign_pdf_timestamped`], and also stores long-term validation
/// data (PAdES-B-LT when timestamped): the certificates and their current
/// revocation status, fetched through `fetch`, for this signature and any
/// earlier ones. The signer's own status is fetched first, and signing
/// stops if it is revoked or cannot be checked. Returns the signed PDF and
/// any problems with the optional data (earlier signers, the TSA).
pub fn sign_pdf_lt(
    input: &[u8],
    signer: &mut dyn Signer,
    options: &SignOptions,
    tsa: Option<&mut dyn TimestampAuthority>,
    fetch: &mut dyn Fetch,
) -> Result<(Vec<u8>, Vec<String>), PdfError> {
    let mut collector = Collector::new(fetch);
    let mut pool: Vec<&[u8]> = options.chain.iter().map(Vec::as_slice).collect();
    pool.extend(ca::BUNDLED);
    collector.require(signer.certificate_der(), &pool)?;
    let signed = sign_pdf_timestamped(input, signer, options, tsa)?;
    collector.collect_document(&signed);
    let (data, warnings) = collector.into_data();
    Ok((add_dss(&signed, &data)?, warnings))
}

fn add_signature_objects(
    inc: &mut IncrementalDocument,
    options: &SignOptions,
    time: SystemTime,
    cert_der: &[u8],
) -> Result<(), PdfError> {
    let prev = inc.get_prev_documents();
    let root_id = prev
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(PdfError::Structure)?;
    let pages = prev.get_pages();
    let page_count = pages.len() as u32;
    let page_no = match &options.appearance {
        Some(Appearance { page: Some(n), .. }) => *n,
        Some(_) => page_count,
        None => 1,
    };
    let page_id = *pages
        .get(&page_no)
        .ok_or(PdfError::Page(page_no, page_count))?;
    let field_name = unused_field_name(prev, root_id);
    let rect = options.appearance.as_ref().map(|a| {
        a.rect.unwrap_or_else(|| {
            let [x, y, ..] = media_box(prev, page_id);
            let m = appearance::DEFAULT_MARGIN;
            let (w, h) = appearance::DEFAULT_SIZE;
            [x + m, y + m, x + m + w, y + m + h]
        })
    });
    add_objects(
        inc,
        options,
        time,
        cert_der,
        root_id,
        page_id,
        &field_name,
        rect,
    )
    .map_err(PdfError::Structure)
}

#[allow(clippy::too_many_arguments)]
fn add_objects(
    inc: &mut IncrementalDocument,
    options: &SignOptions,
    time: SystemTime,
    cert_der: &[u8],
    root_id: ObjectId,
    page_id: ObjectId,
    field_name: &str,
    rect: Option<[f32; 4]>,
) -> lopdf::Result<()> {
    let mut sig = Dictionary::new();
    sig.set("Type", Object::Name(b"Sig".to_vec()));
    sig.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    sig.set("SubFilter", Object::Name(b"ETSI.CAdES.detached".to_vec()));
    sig.set(
        "ByteRange",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(BYTE_RANGE_PLACEHOLDER),
            Object::Integer(BYTE_RANGE_PLACEHOLDER),
            Object::Integer(BYTE_RANGE_PLACEHOLDER),
        ]),
    );
    sig.set(
        "Contents",
        Object::String(vec![0; SIGNATURE_CAPACITY], StringFormat::Hexadecimal),
    );
    sig.set("M", Object::string_literal(pdf_date(time)));
    if let Some(reason) = &options.reason {
        sig.set("Reason", text_string(reason));
    }
    if let Some(location) = &options.location {
        sig.set("Location", text_string(location));
    }
    let sig_id = inc.new_document.add_object(sig);

    let mut widget = Dictionary::new();
    widget.set("Type", Object::Name(b"Annot".to_vec()));
    widget.set("Subtype", Object::Name(b"Widget".to_vec()));
    widget.set("FT", Object::Name(b"Sig".to_vec()));
    widget.set("T", text_string(field_name));
    widget.set("V", Object::Reference(sig_id));
    // Print | Locked
    widget.set("F", Object::Integer(4 | 128));
    match rect {
        Some([x1, y1, x2, y2]) => {
            widget.set(
                "Rect",
                Object::Array(vec![x1.into(), y1.into(), x2.into(), y2.into()]),
            );
            let unix = time
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            let lines = appearance::lines(
                cert_der,
                &crate::verify::format_utc(unix),
                options.reason.as_deref(),
                options.location.as_deref(),
            );
            let ap = inc.new_document.add_object(appearance::stream(
                (x2 - x1).abs(),
                (y2 - y1).abs(),
                &lines,
            ));
            let mut ap_dict = Dictionary::new();
            ap_dict.set("N", Object::Reference(ap));
            widget.set("AP", Object::Dictionary(ap_dict));
        }
        None => widget.set(
            "Rect",
            Object::Array(vec![0.into(), 0.into(), 0.into(), 0.into()]),
        ),
    }
    widget.set("P", Object::Reference(page_id));
    let widget_id = inc.new_document.add_object(widget);

    append_to_array_entry(inc, page_id, b"Annots", widget_id)?;

    // AcroForm: a reference to its own object, inline in the catalog, or absent.
    let acroform = inc
        .get_prev_documents()
        .get_dictionary(root_id)?
        .get(b"AcroForm")
        .ok()
        .cloned();
    match acroform {
        Some(Object::Reference(form_id)) => {
            append_to_array_entry(inc, form_id, b"Fields", widget_id)?;
            set_sig_flags(inc, form_id)?;
        }
        Some(Object::Dictionary(_)) => {
            inc.opt_clone_object_to_new_document(root_id)?;
            let fields = resolved_array(inc, root_id, &[b"AcroForm", b"Fields"])?;
            let root = inc.new_document.get_object_mut(root_id)?.as_dict_mut()?;
            let form = root.get_mut(b"AcroForm")?.as_dict_mut()?;
            let mut fields = fields;
            fields.push(Object::Reference(widget_id));
            form.set("Fields", Object::Array(fields));
            form.set("SigFlags", Object::Integer(3));
        }
        _ => {
            let mut form = Dictionary::new();
            form.set("Fields", Object::Array(vec![Object::Reference(widget_id)]));
            form.set("SigFlags", Object::Integer(3));
            let form_id = inc.new_document.add_object(form);
            inc.opt_clone_object_to_new_document(root_id)?;
            inc.new_document
                .get_object_mut(root_id)?
                .as_dict_mut()?
                .set("AcroForm", Object::Reference(form_id));
        }
    }

    clean_trailer(inc);
    Ok(())
}

/// Keys describing the previous cross-reference stream must not leak into
/// the new trailer.
pub(crate) fn clean_trailer(inc: &mut IncrementalDocument) {
    for key in [b"Index".as_slice(), b"DecodeParms", b"XRefStm", b"Filter"] {
        inc.new_document.trailer.remove(key);
    }
}

/// The page's `/MediaBox`, which may be inherited from its parents; A4
/// when absent.
fn media_box(doc: &Document, page_id: ObjectId) -> [f32; 4] {
    let mut node = doc.get_dictionary(page_id).ok();
    for _ in 0..32 {
        let Some(d) = node else { break };
        if let Ok(arr) = d
            .get(b"MediaBox")
            .and_then(|o| doc.dereference(o))
            .and_then(|(_, o)| o.as_array())
        {
            let nums: Vec<f32> = arr.iter().filter_map(|o| o.as_float().ok()).collect();
            if let [a, b, c, e] = nums[..] {
                return [a.min(c), b.min(e), a.max(c), b.max(e)];
            }
        }
        node = d
            .get(b"Parent")
            .and_then(Object::as_reference)
            .and_then(|id| doc.get_dictionary(id))
            .ok();
    }
    [0.0, 0.0, 595.0, 842.0]
}

/// Appends `item` to the array under `key` in dictionary object `owner`,
/// whether that array is inline, its own object, or missing.
fn append_to_array_entry(
    inc: &mut IncrementalDocument,
    owner: ObjectId,
    key: &[u8],
    item: ObjectId,
) -> lopdf::Result<()> {
    inc.opt_clone_object_to_new_document(owner)?;
    let current = inc
        .new_document
        .get_object(owner)?
        .as_dict()?
        .get(key)
        .ok()
        .cloned();
    match current {
        Some(Object::Reference(array_id)) => {
            inc.opt_clone_object_to_new_document(array_id)?;
            inc.new_document
                .get_object_mut(array_id)?
                .as_array_mut()?
                .push(Object::Reference(item));
        }
        Some(Object::Array(mut items)) => {
            items.push(Object::Reference(item));
            inc.new_document
                .get_object_mut(owner)?
                .as_dict_mut()?
                .set(key, Object::Array(items));
        }
        _ => {
            inc.new_document
                .get_object_mut(owner)?
                .as_dict_mut()?
                .set(key, Object::Array(vec![Object::Reference(item)]));
        }
    }
    Ok(())
}

fn set_sig_flags(inc: &mut IncrementalDocument, form_id: ObjectId) -> lopdf::Result<()> {
    inc.opt_clone_object_to_new_document(form_id)?;
    inc.new_document
        .get_object_mut(form_id)?
        .as_dict_mut()?
        .set("SigFlags", Object::Integer(3));
    Ok(())
}

/// Follows `path` of dictionary keys from object `start` and returns the
/// array found there (dereferenced), or an empty one.
fn resolved_array(
    inc: &IncrementalDocument,
    start: ObjectId,
    path: &[&[u8]],
) -> lopdf::Result<Vec<Object>> {
    let doc = &inc.new_document;
    let prev = inc.get_prev_documents();
    let lookup = |id: ObjectId| doc.get_object(id).or_else(|_| prev.get_object(id));
    let mut obj = lookup(start)?;
    for key in path {
        let dict = match obj {
            Object::Reference(id) => lookup(*id)?.as_dict()?,
            o => o.as_dict()?,
        };
        match dict.get(key) {
            Ok(next) => obj = next,
            Err(_) => return Ok(Vec::new()),
        }
    }
    let obj = match obj {
        Object::Reference(id) => lookup(*id)?,
        o => o,
    };
    Ok(obj.as_array().cloned().unwrap_or_default())
}

/// "Firma", "Firma2", ... whichever is not already a field name.
fn unused_field_name(doc: &Document, root_id: ObjectId) -> String {
    let mut taken = Vec::new();
    let fields = doc
        .get_dictionary(root_id)
        .and_then(|root| root.get(b"AcroForm"))
        .and_then(|f| doc.dereference(f))
        .and_then(|(_, f)| f.as_dict())
        .and_then(|f| f.get(b"Fields"))
        .and_then(|f| doc.dereference(f))
        .and_then(|(_, f)| f.as_array());
    if let Ok(fields) = fields {
        for f in fields {
            if let Ok((_, Object::Dictionary(d))) = doc.dereference(f)
                && let Ok(Object::String(t, _)) = d.get(b"T")
            {
                taken.push(t.clone());
            }
        }
    }
    (1..)
        .map(|n| {
            if n == 1 {
                "Firma".to_owned()
            } else {
                format!("Firma{n}")
            }
        })
        .find(|name| !taken.iter().any(|t| t == name.as_bytes()))
        .expect("infinite range")
}

/// PDF text string: PDFDocEncoding-compatible ASCII as is, anything else as
/// UTF-16BE with a BOM.
fn text_string(s: &str) -> Object {
    if s.is_ascii() {
        Object::string_literal(s)
    } else {
        let mut bytes = vec![0xFE, 0xFF];
        for unit in s.encode_utf16() {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        Object::String(bytes, StringFormat::Hexadecimal)
    }
}

/// Locates the placeholders written after `prev_len`, writes the real
/// `/ByteRange` in place (space-padded to the same width) and returns the
/// offsets of the `<` and one past the `>` of `/Contents`.
fn fill_byte_range(out: &mut [u8], prev_len: usize) -> Result<(usize, usize), PdfError> {
    let mut hole = Vec::with_capacity(2 * SIGNATURE_CAPACITY + 2);
    hole.push(b'<');
    hole.resize(1 + 2 * SIGNATURE_CAPACITY, b'0');
    hole.push(b'>');
    let contents_start = prev_len + find(&out[prev_len..], &hole).ok_or(PdfError::Placeholder)?;
    let contents_end = contents_start + hole.len();

    let marker = b"/ByteRange";
    let br = prev_len + find(&out[prev_len..], marker).ok_or(PdfError::Placeholder)?;
    let open = br + find(&out[br..], b"[").ok_or(PdfError::Placeholder)?;
    let close = open + find(&out[open..], b"]").ok_or(PdfError::Placeholder)?;

    let value = format!(
        "[0 {} {} {}",
        contents_start,
        contents_end,
        out.len() - contents_end
    );
    let width = close - open;
    if value.len() > width {
        return Err(PdfError::Placeholder);
    }
    let padded = format!("{value:<width$}");
    out[open..close].copy_from_slice(padded.as_bytes());
    Ok((contents_start, contents_end))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// `D:YYYYMMDDHHmmSSZ` in UTC.
fn pdf_date(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "D:{y:04}{m:02}{d:02}{:02}{:02}{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to (year, month, day), from Howard Hinnant's
/// `civil_from_days`.
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(pdf_date(UNIX_EPOCH), "D:19700101000000Z");
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1_792_929_845);
        assert_eq!(pdf_date(t), "D:20261025120405Z");
    }
}
