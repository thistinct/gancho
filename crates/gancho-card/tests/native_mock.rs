//! Drives the native backend against a simulated cédula that follows the
//! documented IAS-ECC behaviour, including T=0 style `61 xx` chaining.

use gancho_card::native::{Card, NativeError, NativeSigner, PinStatus, Transport};
use gancho_core::Signer;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};
use rsa::signature::Verifier;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha2::Sha256;

const CERT: &[u8] = include_bytes!("fixtures/test-cert.der");
const KEY: &str = include_str!("fixtures/test-key.pem");
const PIN: &[u8] = b"1234";
const AID: [u8; 12] = [
    0xA0, 0x00, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x01, 0x63, 0x42, 0x00,
];

struct MockCard {
    key: RsaPrivateKey,
    /// Certificate file contents, padded past the DER end like real cards.
    cert_file: Vec<u8>,
    tries: u8,
    app_selected: bool,
    file_selected: bool,
    verified: bool,
    dst_set: bool,
    digest: Option<Vec<u8>>,
    pending: Vec<u8>,
    /// Every VERIFY that carried a PIN.
    pin_attempts: usize,
}

impl MockCard {
    fn new(tries: u8) -> Self {
        let mut cert_file = CERT.to_vec();
        cert_file.extend_from_slice(&[0u8; 37]);
        Self {
            key: RsaPrivateKey::from_pkcs8_pem(KEY).unwrap(),
            cert_file,
            tries,
            app_selected: false,
            file_selected: false,
            verified: false,
            dst_set: false,
            digest: None,
            pending: Vec::new(),
            pin_attempts: 0,
        }
    }

    /// Queue `data` for GET RESPONSE and answer `61 xx`.
    fn chain(&mut self, data: Vec<u8>) -> Vec<u8> {
        self.pending = data;
        vec![0x61, self.pending.len().min(256) as u8]
    }

    fn sw(sw: u16) -> Vec<u8> {
        sw.to_be_bytes().to_vec()
    }
}

impl Transport for MockCard {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, NativeError> {
        let (cla, ins, p1, p2) = (apdu[0], apdu[1], apdu[2], apdu[3]);
        assert_eq!(cla, 0x00);
        let data = if apdu.len() > 5 {
            &apdu[5..5 + apdu[4] as usize]
        } else {
            &[][..]
        };
        Ok(match (ins, p1, p2) {
            (0xA4, 0x04, 0x00) => {
                if data == AID {
                    self.app_selected = true;
                    self.chain(vec![0x6F, 0x00])
                } else {
                    Self::sw(0x6A82)
                }
            }
            (0xA4, 0x00, 0x00) => {
                assert!(self.app_selected, "file selected before the application");
                if data == [0xB0, 0x01] {
                    self.file_selected = true;
                    let n = self.cert_file.len();
                    self.chain(vec![0x6F, 0x04, 0x80, 0x02, (n >> 8) as u8, n as u8])
                } else {
                    Self::sw(0x6A82)
                }
            }
            (0xA4, _, _) => Self::sw(0x6A86),
            (0xC0, _, _) => {
                let n = self.pending.len().min(256);
                let mut out: Vec<u8> = self.pending.drain(..n).collect();
                if self.pending.is_empty() {
                    out.extend_from_slice(&[0x90, 0x00]);
                } else {
                    out.extend_from_slice(&[0x61, self.pending.len().min(256) as u8]);
                }
                out
            }
            (0xB0, hi, lo) => {
                assert!(self.file_selected);
                let off = (hi as usize) << 8 | lo as usize;
                let le = apdu[4] as usize;
                let end = (off + le).min(self.cert_file.len());
                let mut out = self.cert_file[off..end].to_vec();
                out.extend_from_slice(&[0x90, 0x00]);
                out
            }
            (0x20, 0x00, 0x11) if data.is_empty() => match (self.verified, self.tries) {
                (true, _) => Self::sw(0x9000),
                (_, 0) => Self::sw(0x6983),
                (_, n) => Self::sw(0x63C0 | n as u16),
            },
            (0x20, 0x00, 0x11) => {
                self.pin_attempts += 1;
                assert_eq!(data.len(), 12, "PIN must be padded to 12 bytes");
                if self.tries == 0 {
                    return Ok(Self::sw(0x6983));
                }
                let pin: Vec<u8> = data.iter().copied().take_while(|b| *b != 0).collect();
                if pin == PIN {
                    self.verified = true;
                    self.tries = 3;
                    Self::sw(0x9000)
                } else {
                    self.tries -= 1;
                    if self.tries == 0 {
                        Self::sw(0x6983)
                    } else {
                        Self::sw(0x63C0 | self.tries as u16)
                    }
                }
            }
            (0x22, 0x41, 0xB6) => {
                assert_eq!(data, [0x80, 0x01, 0x42, 0x84, 0x01, 0x01]);
                self.dst_set = true;
                Self::sw(0x9000)
            }
            (0x2A, 0x90, 0xA0) => {
                assert_eq!(&data[..2], &[0x90, 0x20]);
                self.digest = Some(data[2..].to_vec());
                Self::sw(0x6120)
            }
            (0x2A, 0x9E, 0x9A) => {
                if !self.verified {
                    return Ok(Self::sw(0x6982));
                }
                assert!(self.dst_set);
                let digest = self.digest.take().expect("PSO:HASH before PSO:CDS");
                let sig = self
                    .key
                    .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
                    .unwrap();
                self.chain(sig)
            }
            _ => Self::sw(0x6D00),
        })
    }
}

fn verify(cert_der: &[u8], msg: &[u8], sig: &[u8]) {
    let key = RsaPrivateKey::from_pkcs8_pem(KEY).unwrap();
    let spki = key.to_public_key().to_public_key_der().unwrap();
    let vk = VerifyingKey::<Sha256>::new(
        rsa::RsaPublicKey::from_public_key_der(spki.as_bytes()).unwrap(),
    );
    vk.verify(msg, &Signature::try_from(sig).unwrap()).unwrap();
    assert_eq!(cert_der, CERT);
}

#[test]
fn reads_certificate_without_padding() {
    let mut card = Card::new(MockCard::new(3)).unwrap();
    assert_eq!(card.certificate().unwrap(), CERT);
}

#[test]
fn signs_and_signature_verifies() {
    let card = Card::new(MockCard::new(3)).unwrap();
    let mut signer = NativeSigner::new(card, "1234").unwrap();
    let msg = b"hola";
    let sig = signer.sign_sha256_rsa(msg).unwrap();
    assert_eq!(sig.len(), 256);
    verify(signer.certificate_der(), msg, &sig);
    // One VERIFY covers several signatures.
    let sig2 = signer.sign_sha256_rsa(b"chau").unwrap();
    verify(signer.certificate_der(), b"chau", &sig2);
}

#[test]
fn wrong_pin_reports_tries_left() {
    let mut card = Card::new(MockCard::new(3)).unwrap();
    assert!(matches!(
        card.verify_pin("9999"),
        Err(NativeError::WrongPin(2))
    ));
    assert_eq!(card.pin_status().unwrap(), PinStatus::TriesLeft(2));
}

#[test]
fn refuses_to_spend_last_try() {
    let mut card = Card::new(MockCard::new(1)).unwrap();
    assert!(matches!(
        card.verify_pin("1234"),
        Err(NativeError::LastPinTry(1))
    ));
}

#[test]
fn blocked_pin_is_not_sent() {
    let mut card = Card::new(MockCard::new(0)).unwrap();
    assert!(matches!(
        card.verify_pin("1234"),
        Err(NativeError::PinBlocked)
    ));
}

#[test]
fn bad_pin_format_is_not_sent() {
    let mut card = Card::new(MockCard::new(3)).unwrap();
    assert!(matches!(card.verify_pin("12"), Err(NativeError::PinFormat)));
    assert!(matches!(
        card.verify_pin("123456789"),
        Err(NativeError::PinFormat)
    ));
    assert!(matches!(
        card.verify_pin("abcd"),
        Err(NativeError::PinFormat)
    ));
    assert!(matches!(
        card.verify_pin("12 34"),
        Err(NativeError::PinFormat)
    ));
    // No attempt reached the card: the retry counter is untouched.
    assert_eq!(card.pin_status().unwrap(), PinStatus::TriesLeft(3));
}

#[test]
fn signing_without_pin_fails() {
    let mut card = Card::new(MockCard::new(3)).unwrap();
    let err = card.sign_sha256_digest(&[0u8; 32]).unwrap_err();
    assert!(matches!(err, NativeError::Status { sw: 0x6982, .. }));
}

#[test]
fn recognises_cedula_atr_patterns() {
    use gancho_card::native::atr_looks_like_cedula;
    // The masked reference ATR (OpenSC cedulauy) and the v4 sample in
    // firmauy's card-protocol notes.
    let reference = [
        0x3B, 0x7F, 0x94, 0x00, 0x00, 0x80, 0x31, 0x80, 0x65, 0xB0, 0x85, 0x03, 0x00, 0xEF, 0x12,
        0x0F, 0xFF, 0x82, 0x90, 0x00,
    ];
    let v4 = [
        0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0x80, 0x65, 0xB0, 0x85, 0x05, 0x00, 0x11, 0x12,
        0x0F, 0xFF, 0x82, 0x90, 0x00,
    ];
    assert!(atr_looks_like_cedula(&reference));
    assert!(atr_looks_like_cedula(&v4));
    // A YubiKey's ATR.
    let yubikey = [
        0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57,
        0x59, 0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
    ];
    assert!(!atr_looks_like_cedula(&yubikey));
}
