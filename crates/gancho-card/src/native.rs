//! Direct card access over PC/SC, with no vendor middleware.
//!
//! Sends the standard IAS-ECC APDUs the cédula answers to:
//! `SELECT app → VERIFY PIN → MSE:SET DST → PSO:HASH → PSO:CDS`.
//! The sequence follows AGESIC's technical documentation as written up in
//! firmauy's `docs/card-protocol.md`
//! (<https://github.com/carlosplanchon/firmauy/blob/main/docs/card-protocol.md>).

use std::ffi::{CStr, CString};

use gancho_core::{SignError, Signer};
use sha2::{Digest, Sha256};

/// IAS application AID; the file system is only reachable after selecting it.
const IAS_AID: [u8; 12] = [
    0xA0, 0x00, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x01, 0x63, 0x42, 0x00,
];
/// EF holding the holder's X.509 signing certificate (readable without PIN).
const CERT_FID: u16 = 0xB001;
/// User PIN reference.
const PIN_REF: u8 = 0x11;
/// Signing private key reference.
const KEY_REF: u8 = 0x01;
/// Algorithm reference for RSA PKCS#1 v1.5 with SHA-256.
const ALGO_SHA256_RSA: u8 = 0x42;
/// The card stores the PIN zero-padded to this length.
const PIN_PADDED_LEN: usize = 12;
const PIN_MIN_LEN: usize = 4;
const PIN_MAX_LEN: usize = 8;
/// READ BINARY chunk size.
const READ_CHUNK: usize = 0xF8;
/// How long to keep retrying when another program holds the card.
const CONNECT_RETRIES: u32 = 10;
const CONNECT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(200);

#[derive(Debug, thiserror::Error)]
pub enum NativeError {
    #[error("no smart card reader found; is the reader plugged in?")]
    NoReader,
    #[error("the smart card service is not running (on Linux, install and start pcscd)")]
    NoService,
    #[error("another program is using the card; close it and try again")]
    CardBusy,
    #[error("no card in the reader")]
    NoCard,
    #[error("the PIN must be {PIN_MIN_LEN} to {PIN_MAX_LEN} digits")]
    PinFormat,
    #[error("wrong PIN, {0} tries left")]
    WrongPin(u8),
    #[error(
        "the PIN is blocked; it has to be unblocked at the Dirección Nacional de Identificación Civil"
    )]
    PinBlocked,
    #[error(
        "only {0} PIN try left; refusing to risk blocking the card. \
         Unblock or reset the PIN before signing with this tool"
    )]
    LastPinTry(u8),
    #[error("card answered {sw:04X} to {what}")]
    Status { what: &'static str, sw: u16 },
    #[error("unexpected card response: {0}")]
    Malformed(&'static str),
    #[error(transparent)]
    Pcsc(#[from] pcsc::Error),
}

/// Sends one APDU and returns the response data followed by SW1 SW2.
pub trait Transport {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, NativeError>;
}

/// PIN retry state, read without spending a try.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    Verified,
    TriesLeft(u8),
    Blocked,
}

struct Response {
    data: Vec<u8>,
    sw: u16,
}

/// The cédula's IAS application over some [`Transport`].
pub struct Card<T: Transport> {
    transport: T,
}

impl<T: Transport> Card<T> {
    /// Wraps a transport and selects the IAS application.
    pub fn new(transport: T) -> Result<Self, NativeError> {
        let mut card = Self { transport };
        card.select_app()?;
        Ok(card)
    }

    fn send(&mut self, apdu: &[u8]) -> Result<Response, NativeError> {
        let mut raw = self.transport.transmit(apdu)?;
        if raw.len() < 2 {
            return Err(NativeError::Malformed(
                "response shorter than a status word",
            ));
        }
        let sw2 = raw.pop().unwrap();
        let sw1 = raw.pop().unwrap();
        Ok(Response {
            data: raw,
            sw: u16::from_be_bytes([sw1, sw2]),
        })
    }

    /// Sends `apdu` and follows `61 xx` with GET RESPONSE until the card is done.
    fn send_collect(&mut self, apdu: &[u8]) -> Result<Response, NativeError> {
        let mut resp = self.send(apdu)?;
        let mut data = std::mem::take(&mut resp.data);
        while resp.sw >> 8 == 0x61 {
            resp = self.send(&[0x00, 0xC0, 0x00, 0x00, resp.sw as u8])?;
            if resp.data.is_empty() && resp.sw >> 8 == 0x61 {
                return Err(NativeError::Malformed("GET RESPONSE returned no data"));
            }
            data.append(&mut resp.data);
        }
        Ok(Response { data, sw: resp.sw })
    }

    fn expect_ok(resp: &Response, what: &'static str) -> Result<(), NativeError> {
        if resp.sw == 0x9000 {
            Ok(())
        } else {
            Err(NativeError::Status { what, sw: resp.sw })
        }
    }

    fn select_app(&mut self) -> Result<(), NativeError> {
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, IAS_AID.len() as u8];
        apdu.extend_from_slice(&IAS_AID);
        let resp = self.send_collect(&apdu)?;
        Self::expect_ok(&resp, "SELECT application")
    }

    fn read_file(&mut self, fid: u16) -> Result<Vec<u8>, NativeError> {
        let [hi, lo] = fid.to_be_bytes();
        let resp = self.send_collect(&[0x00, 0xA4, 0x00, 0x00, 0x02, hi, lo, 0x00])?;
        Self::expect_ok(&resp, "SELECT file")?;
        let size =
            fci_file_size(&resp.data).ok_or(NativeError::Malformed("no file size in FCI"))?;

        let mut out = Vec::with_capacity(size);
        while out.len() < size {
            let offset = out.len();
            if offset > 0x7FFF {
                return Err(NativeError::Malformed("file too large for READ BINARY"));
            }
            let chunk = (size - offset).min(READ_CHUNK) as u8;
            let resp = self.send(&[0x00, 0xB0, (offset >> 8) as u8, offset as u8, chunk])?;
            Self::expect_ok(&resp, "READ BINARY")?;
            if resp.data.is_empty() {
                return Err(NativeError::Malformed("READ BINARY returned no data"));
            }
            out.extend_from_slice(&resp.data);
        }
        Ok(out)
    }

    /// DER-encoded signing certificate. The file may be padded past the end
    /// of the certificate, so it is cut to the DER length.
    pub fn certificate(&mut self) -> Result<Vec<u8>, NativeError> {
        let mut der = self.read_file(CERT_FID)?;
        let len = der_total_length(&der).ok_or(NativeError::Malformed("certificate is not DER"))?;
        if len > der.len() {
            return Err(NativeError::Malformed(
                "certificate file shorter than its DER length",
            ));
        }
        der.truncate(len);
        Ok(der)
    }

    /// Reads the PIN retry counter with an empty VERIFY, which spends no try.
    pub fn pin_status(&mut self) -> Result<PinStatus, NativeError> {
        let resp = self.send(&[0x00, 0x20, 0x00, PIN_REF])?;
        match resp.sw {
            0x9000 => Ok(PinStatus::Verified),
            0x6983 => Ok(PinStatus::Blocked),
            sw if sw & 0xFFF0 == 0x63C0 => Ok(PinStatus::TriesLeft((sw & 0x0F) as u8)),
            sw => Err(NativeError::Status {
                what: "PIN status",
                sw,
            }),
        }
    }

    /// Verifies the user PIN. Checks the format and the retry counter first,
    /// and refuses to spend the last remaining try.
    pub fn verify_pin(&mut self, pin: &str) -> Result<(), NativeError> {
        let pin = pin.as_bytes();
        if !(PIN_MIN_LEN..=PIN_MAX_LEN).contains(&pin.len()) || !pin.iter().all(u8::is_ascii_digit)
        {
            return Err(NativeError::PinFormat);
        }
        match self.pin_status()? {
            PinStatus::Verified => return Ok(()),
            PinStatus::Blocked => return Err(NativeError::PinBlocked),
            PinStatus::TriesLeft(n) if n <= 1 => return Err(NativeError::LastPinTry(n)),
            PinStatus::TriesLeft(_) => {}
        }
        let mut apdu = vec![0x00, 0x20, 0x00, PIN_REF, PIN_PADDED_LEN as u8];
        apdu.extend_from_slice(pin);
        apdu.resize(5 + PIN_PADDED_LEN, 0x00);
        let resp = self.send(&apdu);
        apdu.fill(0);
        match resp?.sw {
            0x9000 => Ok(()),
            0x6983 => Err(NativeError::PinBlocked),
            sw if sw & 0xFFF0 == 0x63C0 => Err(NativeError::WrongPin((sw & 0x0F) as u8)),
            sw => Err(NativeError::Status { what: "VERIFY", sw }),
        }
    }

    /// Signs a SHA-256 digest with the card's key (RSA PKCS#1 v1.5). The PIN
    /// must have been verified in this card session.
    pub fn sign_sha256_digest(&mut self, digest: &[u8; 32]) -> Result<Vec<u8>, NativeError> {
        let resp = self.send(&[
            0x00,
            0x22,
            0x41,
            0xB6,
            0x06,
            0x80,
            0x01,
            ALGO_SHA256_RSA,
            0x84,
            0x01,
            KEY_REF,
        ])?;
        Self::expect_ok(&resp, "MSE:SET DST")?;

        let mut apdu = vec![0x00, 0x2A, 0x90, 0xA0, 0x22, 0x90, 0x20];
        apdu.extend_from_slice(digest);
        let resp = self.send(&apdu)?;
        // The card echoes the digest as "61 20"; that is success here.
        if resp.sw != 0x9000 && resp.sw >> 8 != 0x61 {
            return Err(NativeError::Status {
                what: "PSO:HASH",
                sw: resp.sw,
            });
        }

        let resp = self.send_collect(&[0x00, 0x2A, 0x9E, 0x9A, 0x00])?;
        Self::expect_ok(&resp, "PSO:CDS")?;
        if resp.data.len() != 256 {
            return Err(NativeError::Malformed("signature is not 256 bytes"));
        }
        Ok(resp.data)
    }
}

/// File size from a SELECT response: tag 80 or 81 inside the FCI template 6F.
fn fci_file_size(fci: &[u8]) -> Option<usize> {
    let body = match fci.first() {
        Some(0x6F) => {
            let (len, start) = ber_length(fci, 1)?;
            fci.get(start..start + len)?
        }
        _ => fci,
    };
    let mut i = 0;
    while i + 2 <= body.len() {
        let tag = body[i];
        let (len, start) = ber_length(body, i + 1)?;
        let value = body.get(start..start + len)?;
        if matches!(tag, 0x80 | 0x81) && !value.is_empty() && value.len() <= 4 {
            return Some(value.iter().fold(0usize, |acc, b| acc << 8 | *b as usize));
        }
        i = start + len;
    }
    None
}

/// Decodes a BER length at `i`, returning (length, index of first value byte).
fn ber_length(b: &[u8], i: usize) -> Option<(usize, usize)> {
    let first = *b.get(i)?;
    if first < 0x80 {
        return Some((first as usize, i + 1));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 3 {
        return None;
    }
    let bytes = b.get(i + 1..i + 1 + n)?;
    Some((
        bytes.iter().fold(0, |acc, x| acc << 8 | *x as usize),
        i + 1 + n,
    ))
}

/// Total length of the DER SEQUENCE at the start of `b`.
fn der_total_length(b: &[u8]) -> Option<usize> {
    if b.first() != Some(&0x30) {
        return None;
    }
    let (len, start) = ber_length(b, 1)?;
    Some(start + len)
}

/// PC/SC transport to a card in a reader.
pub struct PcscTransport {
    card: pcsc::Card,
    buf: Vec<u8>,
}

impl Transport for PcscTransport {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, NativeError> {
        Ok(self.card.transmit(apdu, &mut self.buf)?.to_vec())
    }
}

/// A reader known to the PC/SC service.
#[derive(Debug, Clone)]
pub struct Reader {
    pub name: CString,
    pub has_card: bool,
}

fn context() -> Result<pcsc::Context, NativeError> {
    pcsc::Context::establish(pcsc::Scope::User).map_err(|e| match e {
        pcsc::Error::NoService | pcsc::Error::ServiceStopped => NativeError::NoService,
        e => e.into(),
    })
}

/// Lists readers and whether each has a card inserted.
pub fn readers() -> Result<Vec<Reader>, NativeError> {
    let ctx = context()?;
    let names = match ctx.list_readers_owned() {
        Ok(names) => names,
        Err(pcsc::Error::NoReadersAvailable) => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut states: Vec<_> = names
        .iter()
        .map(|n| pcsc::ReaderState::new(n.as_c_str(), pcsc::State::UNAWARE))
        .collect();
    ctx.get_status_change(std::time::Duration::ZERO, &mut states)?;
    Ok(names
        .into_iter()
        .zip(states)
        .map(|(name, st)| Reader {
            name,
            has_card: st.event_state().contains(pcsc::State::PRESENT),
        })
        .collect())
}

/// Connects to the cédula in `reader`, or in the first reader that has a card.
pub fn connect(reader: Option<&CStr>) -> Result<Card<PcscTransport>, NativeError> {
    let ctx = context()?;
    let name = match reader {
        Some(r) => r.to_owned(),
        None => {
            let all = readers()?;
            if all.is_empty() {
                return Err(NativeError::NoReader);
            }
            all.into_iter()
                .find(|r| r.has_card)
                .ok_or(NativeError::NoCard)?
                .name
        }
    };
    // The signing flow is stateful (VERIFY, MSE, PSO:HASH, PSO:CDS), so the
    // connection is exclusive for its whole life: no other program can send
    // commands in between. Another program may hold the card briefly, so
    // retry for a moment before giving up. Dropping the connection resets the
    // card, which also clears the verified PIN.
    let mut attempt = 0;
    let card = loop {
        match ctx.connect(&name, pcsc::ShareMode::Exclusive, pcsc::Protocols::ANY) {
            Err(pcsc::Error::SharingViolation) if attempt < CONNECT_RETRIES => {
                attempt += 1;
                std::thread::sleep(CONNECT_RETRY_DELAY);
            }
            Err(pcsc::Error::SharingViolation) => return Err(NativeError::CardBusy),
            Err(pcsc::Error::NoSmartcard | pcsc::Error::RemovedCard) => {
                return Err(NativeError::NoCard);
            }
            other => break other?,
        }
    };
    Card::new(PcscTransport {
        card,
        buf: vec![0; pcsc::MAX_BUFFER_SIZE_EXTENDED],
    })
}

/// [`Signer`] backed by a card whose PIN has been verified.
pub struct NativeSigner<T: Transport> {
    card: Card<T>,
    certificate: Vec<u8>,
}

impl<T: Transport> NativeSigner<T> {
    /// Reads the certificate and verifies `pin`.
    pub fn new(mut card: Card<T>, pin: &str) -> Result<Self, NativeError> {
        let certificate = card.certificate()?;
        card.verify_pin(pin)?;
        Ok(Self { card, certificate })
    }
}

impl<T: Transport> Signer for NativeSigner<T> {
    fn certificate_der(&self) -> &[u8] {
        &self.certificate
    }

    fn sign_sha256_rsa(&mut self, data: &[u8]) -> Result<Vec<u8>, SignError> {
        let digest: [u8; 32] = Sha256::digest(data).into();
        self.card.sign_sha256_digest(&digest).map_err(|e| match e {
            NativeError::WrongPin(_) => SignError::WrongPin(e.to_string()),
            NativeError::PinBlocked => SignError::PinBlocked,
            e => SignError::Device(e.to_string()),
        })
    }
}
