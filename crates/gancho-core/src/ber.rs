//! BER to DER, for reading signatures made by other tools.
//!
//! CMS allows BER, and some signers write indefinite lengths (`0x80` ...
//! `00 00`) or split OCTET STRINGs into chunks. The `der` crate only reads
//! DER, so the first element of a buffer is re-encoded here: definite
//! lengths, chunked OCTET STRINGs joined. Anything after that element
//! (such as the zero padding of a PDF `/Contents`) is ignored. Signed
//! attributes are DER already (RFC 5652 5.4), so re-encoding leaves the
//! signed bytes unchanged.

const MAX_DEPTH: usize = 64;

/// DER encoding of the first BER element in `input`, or `None` if it is
/// malformed.
pub(crate) fn to_der(input: &[u8]) -> Option<Vec<u8>> {
    let (element, _) = parse(input, 0)?;
    let mut out = Vec::with_capacity(input.len());
    element.write(&mut out);
    Some(out)
}

enum Element {
    Primitive(Vec<u8>, Vec<u8>),
    Constructed(Vec<u8>, Vec<Element>),
}

impl Element {
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Element::Primitive(tag, content) => {
                out.extend_from_slice(tag);
                write_len(out, content.len());
                out.extend_from_slice(content);
            }
            Element::Constructed(tag, children) => {
                let mut body = Vec::new();
                for c in children {
                    c.write(&mut body);
                }
                out.extend_from_slice(tag);
                write_len(out, body.len());
                out.extend_from_slice(&body);
            }
        }
    }

    /// The bytes of a (possibly chunked) string type.
    fn string_bytes(self) -> Option<Vec<u8>> {
        match self {
            Element::Primitive(_, content) => Some(content),
            Element::Constructed(_, children) => {
                let mut out = Vec::new();
                for c in children {
                    out.extend(c.string_bytes()?);
                }
                Some(out)
            }
        }
    }
}

/// Parses one element; returns it and the number of bytes it took.
fn parse(input: &[u8], depth: usize) -> Option<(Element, usize)> {
    if depth > MAX_DEPTH {
        return None;
    }
    let first = *input.first()?;
    let mut pos = 1;
    if first & 0x1F == 0x1F {
        // High tag number: continues while the top bit is set.
        loop {
            let b = *input.get(pos)?;
            pos += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let tag = input[..pos].to_vec();
    let constructed = first & 0x20 != 0;

    let len_byte = *input.get(pos)?;
    pos += 1;
    let length = match len_byte {
        0x80 => None,
        n if n < 0x80 => Some(n as usize),
        n => {
            let k = (n & 0x7F) as usize;
            if k > 4 {
                return None;
            }
            let bytes = input.get(pos..pos + k)?;
            pos += k;
            Some(bytes.iter().fold(0usize, |acc, b| acc << 8 | *b as usize))
        }
    };

    if !constructed {
        let len = length?;
        let content = input.get(pos..pos + len)?.to_vec();
        return Some((Element::Primitive(tag, content), pos + len));
    }

    let mut children = Vec::new();
    let end = match length {
        Some(len) => {
            let end = pos.checked_add(len).filter(|e| *e <= input.len())?;
            while pos < end {
                let (child, used) = parse(&input[pos..end], depth + 1)?;
                children.push(child);
                pos += used;
            }
            end
        }
        None => loop {
            if input.get(pos..pos + 2)? == [0, 0] {
                break pos + 2;
            }
            let (child, used) = parse(&input[pos..], depth + 1)?;
            children.push(child);
            pos += used;
        },
    };

    // A constructed OCTET STRING is chunks of one value; DER wants it whole.
    let element = if tag == [0x24] {
        Element::Primitive(
            vec![0x04],
            Element::Constructed(tag, children).string_bytes()?,
        )
    } else {
        Element::Constructed(tag, children)
    };
    Some((element, end))
}

fn write_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

#[cfg(test)]
mod tests {
    use super::to_der;

    #[test]
    fn der_passes_through_and_padding_is_dropped() {
        let der = [0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0xAA];
        let mut padded = der.to_vec();
        padded.extend_from_slice(&[0; 10]);
        assert_eq!(to_der(&padded).unwrap(), der);
    }

    #[test]
    fn indefinite_lengths_become_definite() {
        // SEQUENCE (indefinite) { [0] (indefinite) { INTEGER 5 } }
        let ber = [0x30, 0x80, 0xA0, 0x80, 0x02, 0x01, 0x05, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            to_der(&ber).unwrap(),
            [0x30, 0x05, 0xA0, 0x03, 0x02, 0x01, 0x05]
        );
    }

    #[test]
    fn chunked_octet_strings_are_joined() {
        // OCTET STRING (constructed, indefinite) { "ab", "c" }
        let ber = [0x24, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x01, b'c', 0, 0];
        assert_eq!(to_der(&ber).unwrap(), [0x04, 0x03, b'a', b'b', b'c']);
    }

    #[test]
    fn long_definite_lengths_are_minimised() {
        // INTEGER with a needlessly long length form.
        let ber = [0x02, 0x82, 0x00, 0x01, 0x07];
        assert_eq!(to_der(&ber).unwrap(), [0x02, 0x01, 0x07]);
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert!(to_der(&[0x30, 0x80, 0x02, 0x01]).is_none());
        assert!(to_der(&[0x30, 0x05, 0x02]).is_none());
        assert!(to_der(&[]).is_none());
    }
}
