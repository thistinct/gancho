//! Card access through an installed PKCS#11 module: the official Thales
//! Classic Client (`libgclib`) or OpenSC's `cedulauy` driver.

use std::path::{Path, PathBuf};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as P11Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use gancho_core::{SignError, Signer};

/// Environment variable that overrides PKCS#11 module discovery.
pub const MODULE_ENV: &str = "GANCHO_PKCS11_MODULE";

/// Well-known install locations of PKCS#11 modules that can drive the cédula,
/// in order of preference.
pub fn candidate_modules() -> &'static [&'static str] {
    if cfg!(target_os = "windows") {
        &[
            r"C:\Windows\System32\gclib.dll",
            r"C:\Windows\SysWOW64\gclib.dll",
            r"C:\Program Files\Gemalto\Classic Client\BIN\gclib.dll",
            r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
            r"C:\Windows\System32\opensc-pkcs11.dll",
        ]
    } else if cfg!(target_os = "macos") {
        &[
            "/usr/local/lib/ClassicClient/libgclib.dylib",
            "/usr/local/lib/libgclib.dylib",
            "/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib",
            "/Library/OpenSC/lib/opensc-pkcs11.so",
            "/opt/homebrew/lib/opensc-pkcs11.so",
        ]
    } else {
        &[
            "/usr/lib/libgclib.so",
            "/usr/lib/pkcs11/libgclib.so",
            "/usr/lib/ClassicClient/libgclib.so",
            "/usr/lib64/libgclib.so",
            "/usr/lib64/pkcs11/libgclib.so",
            "/usr/local/lib/libgclib.so",
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
            "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
            "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
            "/usr/lib64/opensc-pkcs11.so",
            "/usr/lib/opensc-pkcs11.so",
            "/usr/lib/pkcs11/opensc-pkcs11.so",
            "/usr/local/lib/opensc-pkcs11.so",
        ]
    }
}

/// Pick the module from `GANCHO_PKCS11_MODULE` or the first candidate present.
pub fn find_module() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(MODULE_ENV) {
        return Some(PathBuf::from(p));
    }
    candidate_modules()
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

#[derive(Debug, thiserror::Error)]
pub enum CardError {
    #[error(
        "no PKCS#11 module found; install the cédula middleware (Classic Client) \
         or set {MODULE_ENV} to the driver's path. Looked in:\n  {}",
        candidate_modules().join("\n  ")
    )]
    NoModule,
    #[error("PKCS#11 module {0} does not exist")]
    ModuleMissing(PathBuf),
    #[error("no card found in any reader")]
    NoCard,
    #[error("no signing certificate with a matching private key on the card")]
    NoSigningKey,
    #[error(transparent)]
    Pkcs11(#[from] P11Error),
}

/// A loaded PKCS#11 module.
pub struct Module {
    ctx: Pkcs11,
}

/// A token (inserted card) as reported by the module.
#[derive(Debug, Clone)]
pub struct TokenSummary {
    pub slot: Slot,
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
}

/// A certificate on the card that has a private key with the same `CKA_ID`.
#[derive(Debug, Clone)]
pub struct Credential {
    pub label: String,
    pub id: Vec<u8>,
    pub certificate_der: Vec<u8>,
}

impl Module {
    pub fn load(path: &Path) -> Result<Self, CardError> {
        if !path.exists() {
            return Err(CardError::ModuleMissing(path.to_owned()));
        }
        let ctx = Pkcs11::new(path)?;
        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
        Ok(Self { ctx })
    }

    pub fn load_default() -> Result<Self, CardError> {
        Self::load(&find_module().ok_or(CardError::NoModule)?)
    }

    pub fn tokens(&self) -> Result<Vec<TokenSummary>, CardError> {
        let mut out = Vec::new();
        for slot in self.ctx.get_slots_with_token()? {
            let info = self.ctx.get_token_info(slot)?;
            out.push(TokenSummary {
                slot,
                label: info.label().trim().to_owned(),
                manufacturer: info.manufacturer_id().trim().to_owned(),
                model: info.model().trim().to_owned(),
                serial: info.serial_number().trim().to_owned(),
            });
        }
        Ok(out)
    }

    /// First slot with a token in it.
    pub fn first_token(&self) -> Result<Slot, CardError> {
        self.ctx
            .get_slots_with_token()?
            .into_iter()
            .next()
            .ok_or(CardError::NoCard)
    }

    /// Certificates readable without a PIN. Pairing with private keys needs a
    /// login on most modules, so this lists every X.509 certificate.
    pub fn certificates(&self, slot: Slot) -> Result<Vec<Credential>, CardError> {
        let session = self.ctx.open_ro_session(slot)?;
        read_certificates(&session)
    }

    /// Log in with the user PIN and return a [`Signer`] bound to the card's
    /// signing key.
    pub fn signer(&self, slot: Slot, pin: AuthPin) -> Result<CardSigner, CardError> {
        let session = self.ctx.open_ro_session(slot)?;
        session.login(UserType::User, Some(&pin))?;
        for cred in read_certificates(&session)? {
            let keys = session.find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Id(cred.id.clone()),
            ])?;
            if let Some(&key) = keys.first() {
                return Ok(CardSigner {
                    session,
                    key,
                    credential: cred,
                });
            }
        }
        Err(CardError::NoSigningKey)
    }
}

fn read_certificates(session: &Session) -> Result<Vec<Credential>, CardError> {
    let handles = session.find_objects(&[
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(CertificateType::X_509),
    ])?;
    let mut out = Vec::new();
    for h in handles {
        let mut cred = Credential {
            label: String::new(),
            id: Vec::new(),
            certificate_der: Vec::new(),
        };
        for attr in session.get_attributes(
            h,
            &[
                AttributeType::Label,
                AttributeType::Id,
                AttributeType::Value,
            ],
        )? {
            match attr {
                Attribute::Label(v) => cred.label = String::from_utf8_lossy(&v).into_owned(),
                Attribute::Id(v) => cred.id = v,
                Attribute::Value(v) => cred.certificate_der = v,
                _ => {}
            }
        }
        out.push(cred);
    }
    Ok(out)
}

/// The cédula's signing key in a logged-in session.
pub struct CardSigner {
    session: Session,
    key: ObjectHandle,
    credential: Credential,
}

impl CardSigner {
    pub fn credential(&self) -> &Credential {
        &self.credential
    }
}

impl Signer for CardSigner {
    fn certificate_der(&self) -> &[u8] {
        &self.credential.certificate_der
    }

    fn sign_sha256_rsa(&mut self, data: &[u8]) -> Result<Vec<u8>, SignError> {
        self.session
            .sign(&Mechanism::Sha256RsaPkcs, self.key, data)
            .map_err(|e| match e {
                P11Error::Pkcs11(RvError::PinIncorrect, _) => SignError::WrongPin(e.to_string()),
                P11Error::Pkcs11(RvError::PinLocked, _) => SignError::PinBlocked,
                other => SignError::Device(other.to_string()),
            })
    }
}
