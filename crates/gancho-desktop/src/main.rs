//! Gancho desktop: pick a PDF, enter the PIN, sign it with the cédula;
//! or check the signatures in a PDF. The window is plain HTML in `ui/`;
//! everything that touches the card or the file runs here.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use gancho_card::native::{self, NativeError, NativeSigner, PinStatus};
use gancho_core::Signer;
use gancho_core::appearance::Appearance;
use gancho_core::ca::{self, CertificateSummary};
use gancho_core::ltv::LtvError;
use gancho_core::pdf::{PdfError, SignOptions, sign_pdf_lt, sign_pdf_timestamped};
use gancho_core::revocation::{HttpFetch, Status};
use gancho_core::tsp::{HttpTsa, TimestampAuthority};
use gancho_core::verify::{SignatureReport, format_utc, parse_pdf_date, verify_pdf};
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, UiError>;

/// An error as the window shows it: a short message in plain Spanish that
/// says what to do next, and the technical details behind a toggle.
#[derive(Debug, Serialize)]
struct UiError {
    message: String,
    details: Option<String>,
}

impl UiError {
    fn with_details(message: &str, details: impl ToString) -> Self {
        let details = details.to_string();
        eprintln!("gancho: {message} ({details})");
        Self {
            message: message.into(),
            details: Some(details),
        }
    }
}

impl From<String> for UiError {
    fn from(message: String) -> Self {
        Self {
            message,
            details: None,
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
    /// Timestamp server URL when the time should be certified by it;
    /// otherwise the computer's clock is used.
    tsa: Option<String>,
    /// Store revocation data for long-term validity.
    #[serde(default)]
    lt: bool,
}

#[derive(Serialize)]
struct Signed {
    output: PathBuf,
    /// Problems with optional extras (for example the validation data of
    /// an earlier signer), in plain Spanish.
    notes: Vec<String>,
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

/// `contrato.pdf` → `contrato-firmado.pdf`, in the same folder.
#[tauri::command]
fn default_output(input: PathBuf) -> PathBuf {
    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
    input.with_file_name(format!("{stem}-firmado.pdf"))
}

#[tauri::command]
async fn sign(request: SignRequest) -> Result<Signed> {
    blocking(move || {
        // Checked before the PIN is used.
        if same_file(&request.input, &request.output) {
            return Err("elegí otro nombre: el original no se sobrescribe".into());
        }
        let input = std::fs::read(&request.input)
            .map_err(|e| UiError::with_details("No se pudo abrir el PDF.", e))?;
        let _guard = CARD.lock().unwrap_or_else(|e| e.into_inner());
        let card = native::connect(None)?;
        let mut signer = NativeSigner::new(card, &request.pin)?;
        drop(request.pin);

        let options = SignOptions {
            reason: non_empty(request.reason),
            location: non_empty(request.location),
            chain: ca::issuer_chain(signer.certificate_der(), ca::BUNDLED),
            appearance: request.visible.then(Appearance::default),
            ..Default::default()
        };
        let mut tsa = non_empty(request.tsa).map(HttpTsa);
        let tsa = tsa.as_mut().map(|t| t as &mut dyn TimestampAuthority);
        let (signed, warnings) = if request.lt {
            sign_pdf_lt(&input, &mut signer, &options, tsa, &mut HttpFetch)
        } else {
            sign_pdf_timestamped(&input, &mut signer, &options, tsa).map(|s| (s, Vec::new()))
        }
        .map_err(sign_error)?;
        drop(signer);
        std::fs::write(&request.output, signed)
            .map_err(|e| UiError::with_details("No se pudo guardar el PDF firmado.", e))?;
        for w in &warnings {
            eprintln!("gancho: {w}");
        }
        let notes = if warnings.is_empty() {
            Vec::new()
        } else {
            vec![
                "No se pudo guardar el estado de todos los certificados (por ejemplo, el de \
                una firma anterior o el del sello de tiempo). El de tu firma sí quedó guardado."
                    .to_owned(),
            ]
        };
        Ok(Signed {
            output: request.output,
            notes,
        })
    })
    .await
}

fn sign_error(e: PdfError) -> UiError {
    let message = match &e {
        PdfError::Ltv(LtvError::Revoked { at, .. }) => format!(
            "Tu certificado fue revocado el {}. No se puede usar para firmar.",
            &format_utc(*at)[..10]
        ),
        PdfError::Ltv(_) => "No se pudo consultar si tu certificado está vigente. Revisá la \
            conexión a internet y probá de nuevo, o firmá sin validez a largo plazo."
            .to_owned(),
        PdfError::Cms(gancho_core::cms::CmsError::Timestamp(_)) => "No se pudo obtener el \
            sello de tiempo. Revisá la conexión a internet y probá de nuevo, o usá la hora de \
            esta computadora."
            .to_owned(),
        PdfError::Certified => "El autor certificó este PDF sin permitir cambios, así que no se \
            puede firmar de nuevo."
            .to_owned(),
        _ => "No se pudo firmar el PDF.".to_owned(),
    };
    UiError::with_details(&message, e)
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

#[tauri::command]
async fn verify(path: PathBuf) -> Result<Vec<Check>> {
    blocking(move || {
        let pdf = std::fs::read(&path)
            .map_err(|e| UiError::with_details("No se pudo abrir el PDF.", e))?;
        let reports = verify_pdf(&pdf, &[], &[])
            .map_err(|e| UiError::with_details("No se pudo leer el PDF.", e))?;
        Ok(reports.iter().map(check_view).collect())
    })
    .await
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
        if !r.covers_whole_file && r.changes_after.is_empty() {
            note(
                true,
                "Después de esta firma solo se agregaron otras firmas o datos de validación."
                    .into(),
            );
        }
        if !r.changes_after.is_empty() {
            note(
                false,
                format!(
                    "El documento se modificó después de esta firma: {}.",
                    r.changes_after.join(", ")
                ),
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
        } else {
            note(
                true,
                "La hora es la de la computadora de quien firmó (sin sello de tiempo).".into(),
            );
        }
        if r.revoked {
            note(
                false,
                "El certificado estaba revocado cuando se firmó.".into(),
            );
        } else if r.revocation.iter().any(|x| {
            x.finding
                .is_some_and(|f| matches!(f.status, Status::Revoked(_)))
        }) {
            note(
                true,
                "El certificado fue revocado después de firmar; la firma sigue valiendo.".into(),
            );
        }
        if r.long_term() {
            note(
                true,
                "Validez a largo plazo: el PDF guarda el estado de los certificados al firmar."
                    .into(),
            );
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
