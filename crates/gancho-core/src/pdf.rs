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
use crate::cms::{CmsError, signed_data_detached};

/// Bytes reserved for the DER signature. A cédula signature with its
/// certificate and the CA chain is about 5 KiB; the rest leaves room for a
/// timestamp token later on.
const SIGNATURE_CAPACITY: usize = 16 * 1024;
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
    #[error("unexpected PDF structure: {0}")]
    Structure(lopdf::Error),
    #[error("could not write the signed PDF: {0}")]
    Write(std::io::Error),
    #[error("signature placeholder not found in the output")]
    Placeholder,
    #[error("the signature is {0} bytes, more than the {SIGNATURE_CAPACITY} reserved")]
    TooLarge(usize),
    #[error(transparent)]
    Cms(#[from] CmsError),
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
}

/// Signs `input` and returns the signed PDF.
pub fn sign_pdf(
    input: &[u8],
    signer: &mut dyn Signer,
    options: &SignOptions,
) -> Result<Vec<u8>, PdfError> {
    let doc = Document::load_mem(input).map_err(PdfError::Parse)?;
    if doc.is_encrypted() {
        return Err(PdfError::Encrypted);
    }
    let mut inc = IncrementalDocument::create_from(input.to_vec(), doc);
    add_signature_objects(&mut inc, options).map_err(PdfError::Structure)?;

    let mut out = Vec::with_capacity(input.len() + 2 * SIGNATURE_CAPACITY + 4096);
    inc.save_to(&mut out).map_err(PdfError::Write)?;

    let (contents_start, contents_end) = fill_byte_range(&mut out, input.len())?;
    let mut hasher = Sha256::new();
    hasher.update(&out[..contents_start]);
    hasher.update(&out[contents_end..]);
    let digest: [u8; 32] = hasher.finalize().into();

    let cms = signed_data_detached(signer, &digest, &options.chain)?;
    if cms.len() > SIGNATURE_CAPACITY {
        return Err(PdfError::TooLarge(cms.len()));
    }
    let hex = hex_upper(&cms);
    out[contents_start + 1..contents_start + 1 + hex.len()].copy_from_slice(hex.as_bytes());
    Ok(out)
}

fn add_signature_objects(
    inc: &mut IncrementalDocument,
    options: &SignOptions,
) -> lopdf::Result<()> {
    let prev = inc.get_prev_documents();
    let root_id = prev.trailer.get(b"Root")?.as_reference()?;
    let page_id = *prev
        .get_pages()
        .get(&1)
        .ok_or(lopdf::Error::PageNumberNotFound(1))?;
    let field_name = unused_field_name(prev, root_id);

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
    sig.set(
        "M",
        Object::string_literal(pdf_date(options.time.unwrap_or_else(SystemTime::now))),
    );
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
    widget.set("T", text_string(&field_name));
    widget.set("V", Object::Reference(sig_id));
    // Print | Locked
    widget.set("F", Object::Integer(4 | 128));
    widget.set(
        "Rect",
        Object::Array(vec![0.into(), 0.into(), 0.into(), 0.into()]),
    );
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

    // Keys describing the previous cross-reference stream must not leak into
    // the new trailer.
    for key in [b"Index".as_slice(), b"DecodeParms", b"XRefStm", b"Filter"] {
        inc.new_document.trailer.remove(key);
    }
    Ok(())
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
