//! What a PDF's later revisions changed after a signature.
//!
//! Each signature covers the file as it was when it was made; later
//! signatures are appended as incremental updates. Those updates are
//! expected to add signature fields, fill empty ones, extend the form and
//! page annotation lists with them, and store validation data (DSS), and
//! may touch the document metadata. Anything else (new page content, a
//! changed annotation, a replaced object) is reported, since it changes
//! what the earlier signers saw.

use lopdf::{Dictionary, Document, Object, ObjectId};

/// Catalog keys an added signature or DSS may change.
const CATALOG_KEYS: &[&[u8]] = &[b"AcroForm", b"DSS", b"Extensions"];
/// AcroForm keys a signature may change.
const ACROFORM_KEYS: &[&[u8]] = &[b"Fields", b"SigFlags", b"DR", b"DA"];
/// Signature field keys set when an empty field is signed.
const FIELD_KEYS: &[&[u8]] = &[b"V", b"AP"];

/// Describes each change in `current` since `signed` (the revision a
/// signature covers) that is not part of adding signatures or validation
/// data. Empty when there are none.
pub(crate) fn after(signed: &Document, current: &Document) -> Vec<String> {
    let root = |d: &Document| d.trailer.get(b"Root").and_then(Object::as_reference).ok();
    let (Some(old_root), Some(new_root)) = (root(signed), root(current)) else {
        return vec!["the document catalog is missing".into()];
    };
    if old_root != new_root {
        return vec!["the document catalog was replaced".into()];
    }
    let ctx = Context {
        signed,
        current,
        root: new_root,
        acroform: [signed, current].map(|d| {
            d.get_dictionary(new_root)
                .and_then(|r| r.get(b"AcroForm"))
                .and_then(Object::as_reference)
                .ok()
        }),
        info: [signed, current]
            .iter()
            .filter_map(|d| d.trailer.get(b"Info").and_then(Object::as_reference).ok())
            .collect(),
        dss: reachable(
            signed,
            signed.catalog().ok().and_then(|r| r.get(b"DSS").ok()),
        ),
    };

    let mut found = Vec::new();
    for (id, new) in &current.objects {
        let Some(old) = signed.objects.get(id) else {
            continue;
        };
        if old != new && !ctx.allowed(*id, old, new) {
            found.push(describe(*id, new));
        }
    }
    for (id, old) in &signed.objects {
        if !current.objects.contains_key(id) && !is_bookkeeping(old) {
            found.push(format!("{} was removed", describe(*id, old)));
        }
    }
    found
}

struct Context<'a> {
    signed: &'a Document,
    current: &'a Document,
    root: ObjectId,
    /// The AcroForm's own object, before and after, when it has one.
    acroform: [Option<ObjectId>; 2],
    info: Vec<ObjectId>,
    /// Objects that belonged to the DSS when the signature was made.
    dss: Vec<ObjectId>,
}

impl Context<'_> {
    fn allowed(&self, id: ObjectId, old: &Object, new: &Object) -> bool {
        if self.dss.contains(&id) || self.info.contains(&id) || is_bookkeeping(old) {
            return true;
        }
        if let (Ok(old), Ok(new)) = (old.as_array(), new.as_array()) {
            // A separate /Annots or /Fields array.
            return self.only_adds_signatures(old, new);
        }
        let (Some(old), Some(new)) = (dict(old), dict(new)) else {
            return false;
        };
        if type_is(new, b"Metadata") {
            return true;
        }
        let changed = changed_keys(old, new);
        if id == self.root {
            return changed.iter().all(|k| CATALOG_KEYS.contains(&k.as_slice()))
                && (!changed.contains(&b"AcroForm".to_vec()) || self.inline_acroform_ok(old, new));
        }
        if self.acroform.contains(&Some(id)) {
            return self.acroform_ok(old, new, &changed);
        }
        if type_is(new, b"Page") {
            return changed == [b"Annots".to_vec()]
                && self.only_adds_signatures(
                    &array(self.signed, old.get(b"Annots").ok()),
                    &array(self.current, new.get(b"Annots").ok()),
                );
        }
        if is_signature_field(self.current, new) {
            // Signing a field that was left empty for it.
            return changed.iter().all(|k| FIELD_KEYS.contains(&k.as_slice()))
                && (!changed.contains(&b"V".to_vec()) || !old.has(b"V"));
        }
        false
    }

    fn inline_acroform_ok(&self, old: &Dictionary, new: &Dictionary) -> bool {
        match (
            old.get(b"AcroForm").ok().and_then(dict),
            new.get(b"AcroForm").ok(),
        ) {
            // The form moved to its own object, or was added.
            (_, Some(Object::Reference(_))) | (None, _) => true,
            (Some(old_form), Some(Object::Dictionary(new_form))) => {
                self.acroform_ok(old_form, new_form, &changed_keys(old_form, new_form))
            }
            _ => false,
        }
    }

    fn acroform_ok(&self, old: &Dictionary, new: &Dictionary, changed: &[Vec<u8>]) -> bool {
        changed
            .iter()
            .all(|k| ACROFORM_KEYS.contains(&k.as_slice()))
            && self.only_adds_signatures(
                &array(self.signed, old.get(b"Fields").ok()),
                &array(self.current, new.get(b"Fields").ok()),
            )
    }

    /// `new` keeps everything in `old` and only adds signature fields.
    fn only_adds_signatures(&self, old: &[Object], new: &[Object]) -> bool {
        old.iter().all(|o| new.contains(o))
            && new.iter().filter(|n| !old.contains(n)).all(|n| {
                self.current
                    .dereference(n)
                    .ok()
                    .and_then(|(_, o)| dict(o))
                    .is_some_and(|d| is_signature_field(self.current, d))
            })
    }
}

fn dict(o: &Object) -> Option<&Dictionary> {
    match o {
        Object::Dictionary(d) => Some(d),
        Object::Stream(s) => Some(&s.dict),
        _ => None,
    }
}

fn type_is(d: &Dictionary, name: &[u8]) -> bool {
    d.get(b"Type")
        .and_then(Object::as_name)
        .is_ok_and(|n| n == name)
}

/// Cross-reference and object streams, which every update rewrites.
fn is_bookkeeping(o: &Object) -> bool {
    dict(o).is_some_and(|d| type_is(d, b"XRef") || type_is(d, b"ObjStm"))
}

/// A signature field or its widget (`/FT /Sig`, possibly inherited).
fn is_signature_field(doc: &Document, d: &Dictionary) -> bool {
    let mut node = Some(d);
    for _ in 0..8 {
        let Some(n) = node else { break };
        if let Ok(ft) = n.get(b"FT").and_then(Object::as_name) {
            return ft == b"Sig";
        }
        node = n
            .get(b"Parent")
            .and_then(Object::as_reference)
            .and_then(|id| doc.get_dictionary(id))
            .ok();
    }
    false
}

fn changed_keys(old: &Dictionary, new: &Dictionary) -> Vec<Vec<u8>> {
    let mut keys: Vec<Vec<u8>> = old
        .iter()
        .chain(new.iter())
        .map(|(k, _)| k.clone())
        .collect();
    keys.sort();
    keys.dedup();
    keys.retain(|k| old.get(k).ok() != new.get(k).ok());
    keys
}

/// An inline array, or the array object a reference points to.
fn array(doc: &Document, o: Option<&Object>) -> Vec<Object> {
    o.and_then(|o| doc.dereference(o).ok())
        .and_then(|(_, o)| o.as_array().ok().cloned())
        .unwrap_or_default()
}

/// Ids of the objects reachable from `start`, a few levels deep (enough
/// for a DSS: dictionary, arrays, VRI entries, streams).
fn reachable(doc: &Document, start: Option<&Object>) -> Vec<ObjectId> {
    let mut found = Vec::new();
    let mut queue: Vec<(&Object, u8)> = start.into_iter().map(|o| (o, 0)).collect();
    while let Some((o, depth)) = queue.pop() {
        if depth > 5 {
            continue;
        }
        let o = match o {
            Object::Reference(id) => {
                if found.contains(id) {
                    continue;
                }
                found.push(*id);
                match doc.get_object(*id) {
                    Ok(o) => o,
                    Err(_) => continue,
                }
            }
            o => o,
        };
        match o {
            Object::Array(items) => queue.extend(items.iter().map(|i| (i, depth + 1))),
            Object::Dictionary(d) => queue.extend(d.iter().map(|(_, v)| (v, depth + 1))),
            _ => {}
        }
    }
    found
}

fn describe(id: ObjectId, o: &Object) -> String {
    let kind = match dict(o) {
        Some(d) if type_is(d, b"Page") => "a page",
        Some(d) if type_is(d, b"Pages") => "the page tree",
        Some(d) if type_is(d, b"Catalog") => "the document catalog",
        Some(d) if type_is(d, b"Annot") || d.has(b"Subtype") && d.has(b"Rect") => "an annotation",
        Some(d) if type_is(d, b"XObject") => "an image or drawing",
        Some(d) if type_is(d, b"Font") => "a font",
        Some(d) if d.has(b"FT") => "a form field",
        _ if matches!(o, Object::Stream(_)) => "page content",
        _ => "an object",
    };
    format!("{kind} (object {})", id.0)
}

/// Whether the document carries a certification (DocMDP) signature that
/// allows no further changes, not even signatures.
pub(crate) fn forbids_changes(doc: &Document) -> bool {
    doc.catalog()
        .ok()
        .and_then(|r| r.get(b"Perms").ok())
        .and_then(|p| doc.dereference(p).ok())
        .and_then(|(_, p)| p.as_dict().ok())
        .and_then(|p| p.get(b"DocMDP").ok())
        .and_then(|s| doc.dereference(s).ok())
        .and_then(|(_, s)| s.as_dict().ok())
        .and_then(|s| docmdp_permissions(doc, s))
        == Some(1)
}

/// The `/P` of a signature's DocMDP transform: 1 no changes, 2 form filling
/// and signing, 3 also annotations. `None` for ordinary signatures.
pub(crate) fn docmdp_permissions(doc: &Document, sig: &Dictionary) -> Option<i64> {
    let refs = sig.get(b"Reference").ok()?;
    let (_, refs) = doc.dereference(refs).ok()?;
    refs.as_array().ok()?.iter().find_map(|r| {
        let (_, r) = doc.dereference(r).ok()?;
        let r = r.as_dict().ok()?;
        if r.get(b"TransformMethod").and_then(Object::as_name).ok()? != b"DocMDP" {
            return None;
        }
        let params = r
            .get(b"TransformParams")
            .ok()
            .and_then(|p| doc.dereference(p).ok())
            .and_then(|(_, p)| p.as_dict().ok());
        Some(
            params
                .and_then(|p| p.get(b"P").and_then(Object::as_i64).ok())
                .unwrap_or(2),
        )
    })
}
