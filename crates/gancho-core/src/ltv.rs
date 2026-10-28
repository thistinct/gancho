//! Long-term validation data (PAdES baseline B-LT).
//!
//! After signing, the certificates of every signer (and timestamp
//! authority) and fresh revocation answers for them (OCSP responses or
//! CRLs) are stored in the PDF's Document Security Store (`/DSS` in the
//! catalog), in one more incremental update. A verifier can then tell that
//! the certificates were not revoked when the document was signed, even
//! after they expire and the CA's servers stop answering for them.
//!
//! The revocation data for the person signing is fetched before the
//! signature is made, so a revoked certificate or an unreachable CA stops
//! the signing instead of producing a file without the data.

use der::{Decode, Encode};
use lopdf::{Dictionary, Document, IncrementalDocument, Object, Stream};
use x509_cert::Certificate;

use crate::ca;
use crate::pdf::{PdfError, clean_trailer};
use crate::revocation::{self, Evidence, Fetch, RevocationError, Status};
use crate::verify::{format_utc, signature_certificates};

#[derive(Debug, thiserror::Error)]
pub enum LtvError {
    #[error("could not check whether the certificate of {subject} is revoked: {source}")]
    Unavailable {
        subject: String,
        source: RevocationError,
    },
    #[error("the certificate of {subject} was revoked on {}", format_utc(*at))]
    Revoked { subject: String, at: i64 },
    #[error("the issuer of {0}'s certificate is not known, so it cannot be checked")]
    NoIssuer(String),
    #[error("unreadable certificate: {0}")]
    Certificate(der::Error),
}

/// Certificates and revocation answers, all DER.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationData {
    pub certs: Vec<Vec<u8>>,
    pub ocsps: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
}

impl ValidationData {
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty() && self.ocsps.is_empty() && self.crls.is_empty()
    }

    fn add_cert(&mut self, der: &[u8]) {
        push_new(&mut self.certs, der);
    }

    fn add(&mut self, evidence: Evidence) {
        match evidence {
            Evidence::Ocsp(r) => {
                for c in revocation::ocsp_certificates(&r) {
                    self.add_cert(&c);
                }
                push_new(&mut self.ocsps, &r);
            }
            Evidence::Crl(c) => push_new(&mut self.crls, &c),
        }
    }
}

fn push_new(list: &mut Vec<Vec<u8>>, item: &[u8]) {
    if !list.iter().any(|i| i == item) {
        list.push(item.to_vec());
    }
}

/// Gathers validation data, asking each CA once.
pub struct Collector<'a> {
    fetch: &'a mut dyn Fetch,
    data: ValidationData,
    /// Certificates already asked about.
    asked: Vec<Vec<u8>>,
    /// Problems with data that was nice to have but not required.
    pub warnings: Vec<String>,
}

impl<'a> Collector<'a> {
    pub fn new(fetch: &'a mut dyn Fetch) -> Self {
        Self {
            fetch,
            data: ValidationData::default(),
            asked: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Gets revocation data for `cert` and every CA above it (found in
    /// `pool`), failing when any of them is revoked or cannot be checked.
    pub fn require(&mut self, cert: &[u8], pool: &[&[u8]]) -> Result<(), LtvError> {
        self.walk(cert, pool, true)
    }

    /// Like [`Collector::require`], but problems only become warnings.
    pub fn collect(&mut self, cert: &[u8], pool: &[&[u8]]) {
        if let Err(e) = self.walk(cert, pool, false) {
            self.warnings.push(e.to_string());
        }
    }

    /// Collects for every signature and signature timestamp in `pdf`.
    pub fn collect_document(&mut self, pdf: &[u8]) {
        let tsa_roots: Vec<&[u8]> = webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .map(|c| c.as_ref())
            .collect();
        for sig in signature_certificates(pdf) {
            let mut pool: Vec<&[u8]> = sig.carried.iter().map(Vec::as_slice).collect();
            pool.extend(ca::BUNDLED);
            self.collect(&sig.signer, &pool);
            if let Some((tsa, carried)) = &sig.timestamp {
                let mut pool: Vec<&[u8]> = carried.iter().map(Vec::as_slice).collect();
                pool.extend(ca::BUNDLED);
                pool.extend(&tsa_roots);
                self.collect(tsa, &pool);
            }
        }
    }

    pub fn into_data(self) -> (ValidationData, Vec<String>) {
        (self.data, self.warnings)
    }

    fn walk(&mut self, cert: &[u8], pool: &[&[u8]], strict: bool) -> Result<(), LtvError> {
        let mut path = vec![cert.to_vec()];
        path.extend(ca::issuer_chain(cert, pool));
        let parsed: Vec<Certificate> = path
            .iter()
            .map(|d| Certificate::from_der(d))
            .collect::<Result<_, _>>()
            .map_err(LtvError::Certificate)?;
        for der in &path {
            self.data.add_cert(der);
        }
        let top = parsed.last().expect("path starts with cert");
        if !ca::is_self_signed(top) {
            let e = LtvError::NoIssuer(subject(top));
            if strict {
                return Err(e);
            }
            self.warnings.push(e.to_string());
        }
        for (i, pair) in parsed.windows(2).enumerate() {
            if self.asked.contains(&path[i]) {
                continue;
            }
            self.asked.push(path[i].clone());
            let (cert, issuer) = (&pair[0], &pair[1]);
            match revocation::fetch(cert, issuer, self.fetch) {
                Ok((evidence, finding)) => {
                    self.data.add(evidence);
                    if let Status::Revoked(at) = finding.status {
                        let e = LtvError::Revoked {
                            subject: subject(cert),
                            at,
                        };
                        if strict {
                            return Err(e);
                        }
                        self.warnings.push(e.to_string());
                    }
                }
                Err(source) => {
                    let e = LtvError::Unavailable {
                        subject: subject(cert),
                        source,
                    };
                    if strict {
                        return Err(e);
                    }
                    self.warnings.push(e.to_string());
                }
            }
        }
        Ok(())
    }
}

fn subject(cert: &Certificate) -> String {
    ca::summarize(&cert.to_der().unwrap_or_default())
        .and_then(|s| s.common_name)
        .unwrap_or_else(|| cert.tbs_certificate.subject.to_string())
}

/// Adds validation data for every signature already in `pdf` (for
/// example one signed earlier without it), as one incremental update.
/// Returns the new file and the problems found along the way.
pub fn add_validation_data(
    pdf: &[u8],
    fetch: &mut dyn Fetch,
) -> Result<(Vec<u8>, Vec<String>), PdfError> {
    let mut collector = Collector::new(fetch);
    collector.collect_document(pdf);
    let (data, warnings) = collector.into_data();
    Ok((add_dss(pdf, &data)?, warnings))
}

/// Appends an incremental update that stores `data` in the document's DSS,
/// keeping whatever it already holds. Returns `pdf` unchanged when
/// everything is already there.
pub fn add_dss(pdf: &[u8], data: &ValidationData) -> Result<Vec<u8>, PdfError> {
    let doc = Document::load_mem(pdf).map_err(PdfError::Parse)?;
    let existing = read_dss(&doc);
    let missing = |new: &[Vec<u8>], old: &[Vec<u8>]| -> Vec<Vec<u8>> {
        new.iter().filter(|n| !old.contains(n)).cloned().collect()
    };
    let add = [
        ("Certs", missing(&data.certs, &existing.certs)),
        ("OCSPs", missing(&data.ocsps, &existing.ocsps)),
        ("CRLs", missing(&data.crls, &existing.crls)),
    ];
    if add.iter().all(|(_, items)| items.is_empty()) {
        return Ok(pdf.to_vec());
    }

    let root_id = doc
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(PdfError::Structure)?;
    let mut dss = dss_dict(&doc).cloned().unwrap_or_default();
    let resolved: Vec<(&str, Vec<Object>)> = add
        .iter()
        .map(|(key, _)| {
            let items = dss
                .get(key.as_bytes())
                .ok()
                .and_then(|o| doc.dereference(o).ok())
                .and_then(|(_, o)| o.as_array().ok().cloned())
                .unwrap_or_default();
            (*key, items)
        })
        .collect();

    let mut inc = IncrementalDocument::create_from(pdf.to_vec(), doc);
    for ((key, mut items), (_, new)) in resolved.into_iter().zip(add) {
        for der in new {
            let id = inc
                .new_document
                .add_object(Stream::new(Dictionary::new(), der));
            items.push(Object::Reference(id));
        }
        if !items.is_empty() {
            dss.set(key, Object::Array(items));
        }
    }
    let dss_id = inc.new_document.add_object(dss);
    (|| -> lopdf::Result<()> {
        inc.opt_clone_object_to_new_document(root_id)?;
        inc.new_document
            .get_object_mut(root_id)?
            .as_dict_mut()?
            .set("DSS", Object::Reference(dss_id));
        Ok(())
    })()
    .map_err(PdfError::Structure)?;
    clean_trailer(&mut inc);

    let mut out = Vec::with_capacity(pdf.len() + 64 * 1024);
    inc.save_to(&mut out).map_err(PdfError::Write)?;
    Ok(out)
}

fn dss_dict(doc: &Document) -> Option<&Dictionary> {
    let root = doc.catalog().ok()?;
    let (_, dss) = doc.dereference(root.get(b"DSS").ok()?).ok()?;
    dss.as_dict().ok()
}

/// What the document's DSS holds.
pub fn read_dss(doc: &Document) -> ValidationData {
    let Some(dss) = dss_dict(doc) else {
        return ValidationData::default();
    };
    let list = |key: &[u8]| -> Vec<Vec<u8>> {
        let Some(items) = dss
            .get(key)
            .ok()
            .and_then(|o| doc.dereference(o).ok())
            .and_then(|(_, o)| o.as_array().ok())
        else {
            return Vec::new();
        };
        items
            .iter()
            .filter_map(|o| doc.dereference(o).ok())
            .filter_map(|(_, o)| o.as_stream().ok())
            .map(|s| {
                s.decompressed_content()
                    .unwrap_or_else(|_| s.content.clone())
            })
            .collect()
    };
    ValidationData {
        certs: list(b"Certs"),
        ocsps: list(b"OCSPs"),
        crls: list(b"CRLs"),
    }
}
