//! Visible signature box: a small stamp on a page with the signer's name,
//! the signing time and, when given, the reason and location.

use lopdf::content::{Content, Operation};
use lopdf::{Dictionary, Object, Stream, dictionary};
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::der::asn1::{Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef};

/// Where to draw the signature box.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Appearance {
    /// 1-based page number; `None` means the last page.
    pub page: Option<u32>,
    /// `[x1, y1, x2, y2]` in PDF points from the page's lower-left corner;
    /// `None` puts a 220×70 box in the lower-left margin.
    pub rect: Option<[f32; 4]>,
}

pub(crate) const DEFAULT_SIZE: (f32, f32) = (220.0, 70.0);
pub(crate) const DEFAULT_MARGIN: f32 = 36.0;

/// The lines shown in the box.
pub(crate) fn lines(
    cert_der: &[u8],
    time: &str,
    reason: Option<&str>,
    location: Option<&str>,
) -> Vec<(bool, String)> {
    let name = Certificate::from_der(cert_der)
        .ok()
        .and_then(|c| common_name(&c))
        .unwrap_or_else(|| "(sin nombre)".into());
    let mut out = vec![
        (false, "Firmado digitalmente por".to_owned()),
        (true, name),
        (false, format!("Fecha: {time}")),
    ];
    if let Some(r) = reason {
        out.push((false, format!("Motivo: {r}")));
    }
    if let Some(l) = location {
        out.push((false, format!("Lugar: {l}")));
    }
    out
}

/// A form XObject of `width`×`height` points drawing `lines` (bold flag,
/// text) inside a thin frame, with the font size chosen to fit.
pub(crate) fn stream(width: f32, height: f32, lines: &[(bool, String)]) -> Stream {
    const PAD: f32 = 5.0;
    const LEADING: f32 = 1.25;
    // Helvetica averages about half an em per character; 0.56 leaves room
    // for capitals, which cédula names are written in.
    let widest = lines
        .iter()
        .map(|(bold, t)| t.chars().count() as f32 * if *bold { 0.62 } else { 0.56 })
        .fold(1.0, f32::max);
    let size = ((width - 2.0 * PAD) / widest)
        .min((height - 2.0 * PAD) / (lines.len() as f32 * LEADING))
        .clamp(3.0, 10.0);

    let mut ops = vec![
        Operation::new("q", vec![]),
        Operation::new("RG", vec![0.15.into(), 0.3.into(), 0.6.into()]),
        Operation::new("w", vec![0.8.into()]),
        Operation::new(
            "re",
            vec![
                0.4.into(),
                0.4.into(),
                (width - 0.8).into(),
                (height - 0.8).into(),
            ],
        ),
        Operation::new("S", vec![]),
        Operation::new("Q", vec![]),
        Operation::new("BT", vec![]),
        Operation::new("rg", vec![0.1.into(), 0.1.into(), 0.1.into()]),
        Operation::new("TL", vec![(size * LEADING).into()]),
        // First baseline: one line height below the top padding.
        Operation::new("Td", vec![PAD.into(), (height - PAD - size).into()]),
    ];
    for (i, (bold, text)) in lines.iter().enumerate() {
        if i > 0 {
            ops.push(Operation::new("T*", vec![]));
        }
        let font = if *bold { "F2" } else { "F1" };
        ops.push(Operation::new(
            "Tf",
            vec![Object::Name(font.into()), size.into()],
        ));
        ops.push(Operation::new(
            "Tj",
            vec![Object::String(win_ansi(text), lopdf::StringFormat::Literal)],
        ));
    }
    ops.push(Operation::new("ET", vec![]));

    let font = |base: &str| {
        Object::Dictionary(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => Object::Name(base.into()),
            "Encoding" => "WinAnsiEncoding",
        })
    };
    let resources: Dictionary = dictionary! {
        "Font" => dictionary! { "F1" => font("Helvetica"), "F2" => font("Helvetica-Bold") },
    };
    Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), width.into(), height.into()],
            "Resources" => resources,
        },
        Content { operations: ops }.encode().unwrap_or_default(),
    )
}

/// Encodes for WinAnsiEncoding: Latin-1 covers Spanish accents and ñ;
/// anything else becomes `?`.
fn win_ansi(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| match c as u32 {
            0x20..=0x7E | 0xA0..=0xFF => c as u8,
            _ => b'?',
        })
        .collect()
}

/// The certificate subject's common name (OID 2.5.4.3).
pub(crate) fn common_name(cert: &Certificate) -> Option<String> {
    cert.tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .find(|atv| atv.oid.to_string() == "2.5.4.3")
        .and_then(|atv| {
            let v = &atv.value;
            v.decode_as::<Utf8StringRef>()
                .map(|s| s.to_string())
                .or_else(|_| v.decode_as::<PrintableStringRef>().map(|s| s.to_string()))
                .or_else(|_| v.decode_as::<TeletexStringRef>().map(|s| s.to_string()))
                .or_else(|_| v.decode_as::<Ia5StringRef>().map(|s| s.to_string()))
                .ok()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_spanish_text() {
        assert_eq!(win_ansi("PÉREZ Ñandú"), b"P\xC9REZ \xD1and\xFA");
        assert_eq!(win_ansi("€ ✓"), b"? ?");
    }

    #[test]
    fn long_names_get_smaller_text() {
        let short = vec![(true, "ANA".to_owned())];
        let long = vec![(
            true,
            "MARÍA FERNANDA RODRÍGUEZ DE LOS SANTOS PÉREZ".to_owned(),
        )];
        let size = |s: &Stream| {
            let c = Content::decode(&s.content).unwrap();
            c.operations
                .iter()
                .find(|o| o.operator == "Tf")
                .unwrap()
                .operands[1]
                .as_float()
                .unwrap()
        };
        assert!(size(&stream(220.0, 70.0, &long)) < size(&stream(220.0, 70.0, &short)));
    }
}
