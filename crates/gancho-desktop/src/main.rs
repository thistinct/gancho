//! Gancho desktop: pick a file, enter the PIN, sign it with the cédula
//! (inside the PDF for PDFs, a separate `.p7s` for anything else); or check
//! the signatures in a PDF or a `.p7s`. The window is plain HTML in `ui/`;
//! everything that touches the card or the file runs here.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use gancho_card::native::{self, NativeError, NativeSigner, PinStatus};
use gancho_core::Signer;
use gancho_core::appearance::Appearance;
use gancho_core::ca::{self, CertificateSummary};
use gancho_core::cades::{DetachedOptions, looks_like_pdf, sign_detached};
use gancho_core::pdf::{SignOptions, sign_pdf_timestamped};
use gancho_core::tsp::{HttpTsa, TimestampAuthority};
use gancho_core::verify::{
    SignatureReport, VerifyError, format_utc, parse_pdf_date, verify_detached, verify_pdf,
};
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, UiError>;

/// An error as the window shows it: a short message in plain Spanish that
/// says what to do next, and the technical details behind a toggle.
#[derive(Debug, Serialize)]
struct UiError {
    message: String,
    details: Option<String>,
    /// Another file the window should ask for and retry with: "signature"
    /// (the `.p7s`) or "data" (the file that was signed).
    #[serde(skip_serializing_if = "Option::is_none")]
    need: Option<&'static str>,
}

impl UiError {
    fn with_details(message: &str, details: impl ToString) -> Self {
        let details = details.to_string();
        eprintln!("gancho: {message} ({details})");
        Self {
            message: message.into(),
            details: Some(details),
            need: None,
        }
    }

    fn needs(need: &'static str, message: &str) -> Self {
        Self {
            need: Some(need),
            ..message.into()
        }
    }
}

impl From<String> for UiError {
    fn from(message: String) -> Self {
        Self {
            message,
            details: None,
            need: None,
        }
    }
}

impl From<&str> for UiError {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}

impl From<NativeError> for UiError {
    fn from(e: NativeError) -> Self {
        const RETRY: &str = "Sacala del lector, volvé a ponerla y tocá Actualizar.";
        let message = match e.cause() {
            NativeError::NoReader => {
                "No se encontró el lector de tarjetas. Conectalo a la computadora y tocá Actualizar."
                    .to_owned()
            }
            NativeError::NoService => "El servicio de tarjetas de la computadora no está \
                funcionando. Reiniciá la computadora y probá de nuevo."
                .to_owned(),
            NativeError::NoCard => "No hay ninguna cédula en el lector. Poné la cédula en el \
                lector y tocá Actualizar."
                .to_owned(),
            // Every reader holds some other card.
            NativeError::NotACedula(_) => "No se encontró la cédula. Poné la cédula en el \
                lector y tocá Actualizar."
                .to_owned(),
            NativeError::CardUnresponsive => format!("La cédula no responde. {RETRY}"),
            NativeError::CardBusy => {
                "Otro programa está usando la cédula. Cerralo y tocá Actualizar.".to_owned()
            }
            NativeError::PinFormat => "El PIN tiene que tener entre 4 y 8 números.".to_owned(),
            NativeError::WrongPin(1) => "PIN incorrecto. Te queda 1 intento.".to_owned(),
            NativeError::WrongPin(n) => format!("PIN incorrecto. Te quedan {n} intentos."),
            NativeError::PinBlocked => "El PIN está bloqueado. Para desbloquearlo hay que ir a \
                la Dirección Nacional de Identificación Civil."
                .to_owned(),
            NativeError::LastPinTry(_) => "Te queda un solo intento de PIN. Para no bloquear la \
                cédula, Gancho no lo usa: desbloqueá o cambiá el PIN en la Dirección Nacional \
                de Identificación Civil."
                .to_owned(),
            _ => format!("No se pudo leer la cédula. {RETRY}"),
        };
        Self::with_details(&message, e)
    }
}

/// Only one card operation at a time: the connection is exclusive, so a
/// lookup started while signing (or a second lookup) would only fail.
static CARD: Mutex<()> = Mutex::new(());

#[derive(Serialize)]
struct Card {
    reader: String,
    name: Option<String>,
    subject: String,
    issuer: String,
    valid_from: String,
    valid_until: String,
    expired: bool,
    /// `None` when the PIN is already verified in this session.
    pin_tries: Option<u8>,
    pin_blocked: bool,
}

#[derive(Deserialize)]
struct SignRequest {
    input: PathBuf,
    output: PathBuf,
    pin: String,
    reason: Option<String>,
    location: Option<String>,
    visible: bool,
    /// Timestamp server URL, when wanted.
    tsa: Option<String>,
}

#[derive(Serialize)]
struct Check {
    field: Option<String>,
    signer: Option<String>,
    time: Option<String>,
    reason: Option<String>,
    location: Option<String>,
    valid: bool,
    /// Human-readable findings, problems first.
    notes: Vec<Note>,
}

#[derive(Serialize)]
struct Note {
    ok: bool,
    text: String,
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

#[tauri::command]
async fn card() -> Result<Card> {
    blocking(|| {
        let _guard = CARD.lock().unwrap_or_else(|e| e.into_inner());
        let readers = native::readers()?;
        let mut card = native::connect(None)?;
        let der = card.certificate()?;
        let summary = ca::summarize(&der).ok_or("No se pudo leer el certificado de la cédula.")?;
        let (pin_tries, pin_blocked) = match card.pin_status()? {
            PinStatus::TriesLeft(n) => (Some(n), false),
            PinStatus::Blocked => (Some(0), true),
            PinStatus::Verified => (None, false),
        };
        let reader = readers
            .iter()
            .find(|r| r.has_card && r.looks_like_cedula())
            .map(|r| r.name.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(card_view(reader, summary, pin_tries, pin_blocked))
    })
    .await
}

fn card_view(
    reader: String,
    s: CertificateSummary,
    pin_tries: Option<u8>,
    pin_blocked: bool,
) -> Card {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    Card {
        reader,
        name: s.common_name,
        subject: s.subject,
        issuer: s.issuer,
        valid_from: format_utc(s.not_before),
        valid_until: format_utc(s.not_after),
        expired: now > s.not_after,
        pin_tries,
        pin_blocked,
    }
}

#[derive(Serialize)]
struct Output {
    path: PathBuf,
    /// The input is a PDF and gets the signature inside it; otherwise the
    /// output is a separate `.p7s` signature.
    pdf: bool,
}

/// `contrato.pdf` → `contrato-firmado.pdf`, or for any other file
/// `contrato.docx` → `contrato.docx.p7s`, in the same folder.
#[tauri::command]
fn default_output(input: PathBuf) -> Output {
    if is_pdf_file(&input) {
        let stem = input.file_stem().unwrap_or_default().to_string_lossy();
        Output {
            path: input.with_file_name(format!("{stem}-firmado.pdf")),
            pdf: true,
        }
    } else {
        Output {
            path: p7s_path(&input),
            pdf: false,
        }
    }
}

fn is_pdf_file(path: &Path) -> bool {
    use std::io::Read;
    let mut head = Vec::with_capacity(1024);
    std::fs::File::open(path)
        .and_then(|f| f.take(1024).read_to_end(&mut head))
        .is_ok_and(|_| looks_like_pdf(&head))
}

fn p7s_path(input: &Path) -> PathBuf {
    let mut name = input.as_os_str().to_owned();
    name.push(".p7s");
    PathBuf::from(name)
}

#[tauri::command]
async fn sign(request: SignRequest) -> Result<PathBuf> {
    blocking(move || {
        // Checked before the PIN is used.
        if same_file(&request.input, &request.output) {
            return Err("elegí otro nombre: el original no se sobrescribe".into());
        }
        let input = std::fs::read(&request.input)
            .map_err(|e| UiError::with_details("No se pudo abrir el archivo.", e))?;
        let _guard = CARD.lock().unwrap_or_else(|e| e.into_inner());
        let card = native::connect(None)?;
        let mut signer = NativeSigner::new(card, &request.pin)?;
        drop(request.pin);
        let chain = ca::issuer_chain(signer.certificate_der(), ca::BUNDLED);
        let mut tsa = non_empty(request.tsa).map(HttpTsa);
        let tsa = tsa.as_mut().map(|t| t as &mut dyn TimestampAuthority);

        if !looks_like_pdf(&input) {
            let options = DetachedOptions {
                chain,
                ..Default::default()
            };
            let p7s = sign_detached(&input, &mut signer, &options, tsa)
                .map_err(|e| UiError::with_details("No se pudo firmar el archivo.", e))?;
            drop(signer);
            std::fs::write(&request.output, p7s)
                .map_err(|e| UiError::with_details("No se pudo guardar la firma.", e))?;
            return Ok(request.output);
        }

        let options = SignOptions {
            reason: non_empty(request.reason),
            location: non_empty(request.location),
            chain,
            appearance: request.visible.then(Appearance::default),
            ..Default::default()
        };
        let signed = sign_pdf_timestamped(&input, &mut signer, &options, tsa)
            .map_err(|e| UiError::with_details("No se pudo firmar el PDF.", e))?;
        drop(signer);
        std::fs::write(&request.output, signed)
            .map_err(|e| UiError::with_details("No se pudo guardar el PDF firmado.", e))?;
        Ok(request.output)
    })
    .await
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Checks the signatures in a PDF, or a detached signature. For the
/// latter `path` is either the `.p7s` or the signed file, and `other` the
/// counterpart the window asked for when it could not be found next to it.
#[tauri::command]
async fn verify(path: PathBuf, other: Option<PathBuf>) -> Result<Vec<Check>> {
    blocking(move || {
        let bytes = read(&path)?;
        if other.is_none() && looks_like_pdf(&bytes) {
            let reports = verify_pdf(&bytes, &[], &[])
                .map_err(|e| UiError::with_details("No se pudo leer el PDF.", e))?;
            // A PDF without signatures inside may have a `.p7s` next to it.
            if !reports.is_empty() || !p7s_path(&path).is_file() {
                return Ok(reports.iter().map(check_view).collect());
            }
        }

        let (sig_path, signature, data) = if is_signature_name(&path) {
            let data = other.or_else(|| {
                let original = path.with_extension("");
                original.is_file().then_some(original)
            });
            (path, bytes, data.as_deref().map(read).transpose()?)
        } else {
            let sig_path = other.unwrap_or_else(|| p7s_path(&path));
            if !sig_path.is_file() {
                return Err(UiError::needs(
                    "signature",
                    "No se encontró la firma de este archivo. Elegí el archivo .p7s.",
                ));
            }
            (sig_path.clone(), read(&sig_path)?, Some(bytes))
        };
        let report = match verify_detached(&signature, data.as_deref(), &[], &[]) {
            Ok(r) => r,
            Err(VerifyError::NoContent) => {
                return Err(UiError::needs(
                    "data",
                    "Elegí el archivo que se firmó con esta firma.",
                ));
            }
            Err(e) => return Err(UiError::with_details("No se pudo leer la firma.", e)),
        };
        let mut check = check_view(&report);
        check.field = sig_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
        Ok(vec![check])
    })
    .await
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| UiError::with_details("No se pudo abrir el archivo.", e))
}

/// `.p7s` and the other names detached CMS signatures go by.
fn is_signature_name(path: &Path) -> bool {
    path.extension().is_some_and(|e| {
        ["p7s", "p7m", "p7b", "sig"].contains(&e.to_string_lossy().to_lowercase().as_str())
    })
}

fn check_view(r: &SignatureReport) -> Check {
    let mut notes = Vec::new();
    let mut note = |ok: bool, text: String| notes.push(Note { ok, text });
    match &r.integrity {
        Ok(()) => note(
            true,
            "El documento no fue modificado desde que se firmó.".into(),
        ),
        Err(e) => note(false, format!("Firma inválida: {e}.")),
    }
    if r.integrity.is_ok() {
        if !r.covers_whole_file {
            note(
                true,
                "Se agregó contenido después de esta firma (por ejemplo, otra firma).".into(),
            );
        }
        if r.trusted {
            note(
                true,
                "El certificado encadena a la raíz nacional de Uruguay.".into(),
            );
        } else {
            note(
                false,
                "El certificado no encadena a una raíz de confianza.".into(),
            );
        }
        match r.valid_at_signing_time {
            Some(true) => note(true, "El certificado estaba vigente al firmar.".into()),
            Some(false) => note(false, "El certificado no estaba vigente al firmar.".into()),
            None => {}
        }
        if let Some(ts) = &r.timestamp {
            match (&ts.integrity, ts.trusted) {
                (Ok(()), trusted) => note(
                    trusted,
                    format!(
                        "Sello de tiempo del {} emitido por {}{}",
                        ts.time.map_or_else(|| "?".into(), format_utc),
                        ts.tsa.as_deref().unwrap_or("una autoridad desconocida"),
                        if trusted {
                            "."
                        } else {
                            " (autoridad no confiable)."
                        }
                    ),
                ),
                (Err(e), _) => note(false, format!("Sello de tiempo inválido: {e}.")),
            }
        }
    }
    notes.sort_by_key(|n| n.ok);
    Check {
        field: r.field.clone(),
        signer: r.signer.clone(),
        time: r
            .signed_at
            .as_deref()
            .map(|t| parse_pdf_date(t).map_or_else(|| t.to_owned(), format_utc)),
        reason: r.reason.clone(),
        location: r.location.clone(),
        valid: r.is_valid(),
        notes,
    }
}

/// Card and file work blocks; keep it off the UI thread.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| UiError::with_details("Algo salió mal. Probá de nuevo.", e))?
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![card, default_output, sign, verify])
        .run(tauri::generate_context!())
        .expect("error while running the Gancho window");
}

#[cfg(test)]
mod tests {
    use super::*;
    use gancho_card::native::ReaderFailure;

    #[test]
    fn unresponsive_cedula_next_to_a_yubikey() {
        let e = UiError::from(NativeError::NotACedula(vec![
            ReaderFailure {
                reader: "Generic EMV Smartcard Reader".into(),
                atr: vec![0x3B],
                error: Box::new(NativeError::CardUnresponsive),
            },
            ReaderFailure {
                reader: "Yubico YubiKey OTP+FIDO+CCID".into(),
                atr: vec![0x3B],
                error: Box::new(NativeError::Status {
                    what: "SELECT application",
                    sw: 0x6A82,
                }),
            },
        ]));
        assert_eq!(
            e.message,
            "La cédula no responde. Sacala del lector, volvé a ponerla y tocá Actualizar."
        );
        assert!(e.details.unwrap().contains("YubiKey"));
    }

    /// A `.p7s` pair is found next to each other, and the window is asked
    /// for whichever half is missing.
    #[test]
    fn finds_or_asks_for_the_other_half() {
        use std::process::Command;
        if Command::new("openssl").arg("version").output().is_err() {
            eprintln!("skipping: openssl not installed");
            return;
        }
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../gancho-core/tests/fixtures");
        let dir = std::env::temp_dir().join(format!("gancho-desktop-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("solo")).unwrap();
        let data = dir.join("nota.txt");
        std::fs::write(&data, "hola").unwrap();
        let ok = Command::new("openssl")
            .args([
                "cms", "-sign", "-binary", "-outform", "DER", "-md", "sha256", "-in",
            ])
            .arg(&data)
            .arg("-signer")
            .arg(fixtures.join("chain-leaf.der"))
            .arg("-inkey")
            .arg(fixtures.join("chain-leaf-key.pem"))
            .arg("-out")
            .arg(dir.join("nota.txt.p7s"))
            .status()
            .unwrap()
            .success();
        assert!(ok);
        let run = |path: PathBuf, other: Option<PathBuf>| {
            tauri::async_runtime::block_on(verify(path, other))
        };

        for path in [data.clone(), dir.join("nota.txt.p7s")] {
            let checks = run(path, None).unwrap();
            assert_eq!(checks[0].field.as_deref(), Some("nota.txt.p7s"));
            // Intact, but the test CA is not a trusted root.
            assert!(
                checks[0]
                    .notes
                    .iter()
                    .any(|n| n.ok && n.text.contains("no fue modificado"))
            );
            assert!(!checks[0].valid);
        }

        std::fs::copy(&data, dir.join("solo/nota.txt")).unwrap();
        std::fs::copy(dir.join("nota.txt.p7s"), dir.join("solo/firma.p7s")).unwrap();
        let e = run(dir.join("solo/nota.txt"), None).err().unwrap();
        assert_eq!(e.need, Some("signature"));
        let e = run(dir.join("solo/firma.p7s"), None).err().unwrap();
        assert_eq!(e.need, Some("data"));
        let checks = run(dir.join("solo/firma.p7s"), Some(dir.join("solo/nota.txt"))).unwrap();
        assert!(
            checks[0]
                .notes
                .iter()
                .any(|n| n.text.contains("no fue modificado"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_other_cards() {
        let e = UiError::from(NativeError::NotACedula(vec![ReaderFailure {
            reader: "Yubico YubiKey OTP+FIDO+CCID".into(),
            atr: vec![0x3B],
            error: Box::new(NativeError::Status {
                what: "SELECT application",
                sw: 0x6A82,
            }),
        }]));
        assert_eq!(
            e.message,
            "No se encontró la cédula. Poné la cédula en el lector y tocá Actualizar."
        );
    }
}
