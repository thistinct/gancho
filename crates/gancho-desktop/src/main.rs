//! Gancho desktop: pick (or drop, or "Open with Gancho") one or more PDFs,
//! enter the PIN once, sign them with the cédula; or check the signatures in
//! a PDF. The window is plain HTML in `ui/`; everything that touches the
//! card or the files runs here.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use gancho_card::native::{self, NativeError, NativeSigner, PinStatus};
use gancho_core::Signer;
use gancho_core::appearance::Appearance;
use gancho_core::ca::{self, CertificateSummary};
use gancho_core::cms::CmsError;
use gancho_core::pdf::{PdfError, SignOptions, sign_pdf_timestamped};
use gancho_core::tsp::{HttpTsa, TimestampAuthority};
use gancho_core::verify::{SignatureReport, format_utc, parse_pdf_date, verify_pdf};
use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tauri::{AppHandle, Emitter, Manager};

type Result<T> = std::result::Result<T, UiError>;

/// An error as the window shows it: a short message in plain Spanish that
/// says what to do next, and the technical details behind a toggle.
#[derive(Debug, Clone, Serialize)]
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
    files: Vec<SignFile>,
    pin: String,
    reason: Option<String>,
    location: Option<String>,
    visible: bool,
    /// Timestamp server URL, when wanted.
    tsa: Option<String>,
}

#[derive(Deserialize)]
struct SignFile {
    input: PathBuf,
    output: PathBuf,
}

/// How one file of a batch went: `saved` when it was signed, `error` when not.
#[derive(Serialize)]
struct Signed {
    input: PathBuf,
    saved: Option<PathBuf>,
    error: Option<UiError>,
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

/// `contrato.pdf` → `contrato-firmado.pdf`, in `folder` or else next to it.
#[tauri::command]
fn default_output(input: PathBuf, folder: Option<PathBuf>) -> PathBuf {
    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
    let name = format!("{stem}-firmado.pdf");
    match folder {
        Some(dir) => dir.join(name),
        None => input.with_file_name(name),
    }
}

/// Signs every file with one PIN entry. `progress` gets the index of each
/// file as its signing starts. A file that can't be signed doesn't stop the
/// others, but a card, PIN or timestamp server problem does, since it would
/// fail them all.
#[tauri::command]
async fn sign(request: SignRequest, progress: Channel<usize>) -> Result<Vec<Signed>> {
    blocking(move || {
        // Checked before the PIN is used.
        let inputs = read_inputs(&request.files)?;
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
        let mut results = Vec::with_capacity(inputs.len());
        let mut stopped = false;
        for (i, (file, pdf)) in request.files.into_iter().zip(inputs).enumerate() {
            if stopped {
                results.push(Signed {
                    input: file.input,
                    saved: None,
                    error: Some("No se firmó por el error anterior.".into()),
                });
                continue;
            }
            let _ = progress.send(i);
            let tsa = tsa.as_mut().map(|t| t as &mut dyn TimestampAuthority);
            let outcome = match sign_pdf_timestamped(&pdf, &mut signer, &options, tsa) {
                Ok(signed) => std::fs::write(&file.output, signed)
                    .map_err(|e| UiError::with_details("No se pudo guardar el PDF firmado.", e)),
                Err(e) => {
                    stopped = fails_every_file(&e);
                    Err(sign_error(e))
                }
            };
            results.push(match outcome {
                Ok(()) => Signed {
                    input: file.input,
                    saved: Some(file.output),
                    error: None,
                },
                Err(e) => Signed {
                    input: file.input,
                    saved: None,
                    error: Some(e),
                },
            });
        }
        Ok(results)
    })
    .await
}

/// Reads every PDF of a batch, refusing outputs that would overwrite an
/// original or each other.
fn read_inputs(files: &[SignFile]) -> Result<Vec<Vec<u8>>> {
    if files.is_empty() {
        return Err("Elegí al menos un PDF.".into());
    }
    for (i, f) in files.iter().enumerate() {
        if files.iter().any(|other| same_file(&other.input, &f.output)) {
            return Err(format!(
                "Elegí otro nombre para {}: el original no se sobrescribe.",
                file_name(&f.output)
            )
            .into());
        }
        if files[..i]
            .iter()
            .any(|other| same_file(&other.output, &f.output))
        {
            return Err(format!(
                "Dos PDFs se guardarían como {}. Elegí otra carpeta o quitá uno.",
                file_name(&f.output)
            )
            .into());
        }
    }
    files
        .iter()
        .map(|f| {
            std::fs::read(&f.input).map_err(|e| {
                UiError::with_details(&format!("No se pudo abrir {}.", file_name(&f.input)), e)
            })
        })
        .collect()
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .unwrap_or(p.as_os_str())
        .to_string_lossy()
        .into_owned()
}

fn fails_every_file(e: &PdfError) -> bool {
    matches!(e, PdfError::Cms(CmsError::Sign(_) | CmsError::Timestamp(_)))
}

fn sign_error(e: PdfError) -> UiError {
    match &e {
        PdfError::Cms(CmsError::Timestamp(_)) => UiError::with_details(
            "No se pudo obtener el sello de tiempo. Revisá la conexión a internet o probá sin sello.",
            e,
        ),
        PdfError::Cms(CmsError::Sign(_)) => UiError::with_details(
            "La cédula no pudo firmar. Sacala del lector, volvé a ponerla y probá de nuevo.",
            e,
        ),
        PdfError::Encrypted => UiError::with_details("El PDF está protegido con contraseña.", e),
        _ => UiError::with_details("No se pudo firmar el PDF.", e),
    }
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

/// PDFs handed to Gancho by the system ("Open with", double click, or a
/// second launch) that the window hasn't picked up yet.
static OPENED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Queues the PDFs among `paths` and tells the window to pick them up. The
/// window also asks once at startup, so files that arrive before it is
/// ready are not lost.
fn open_files(app: &AppHandle, paths: impl IntoIterator<Item = PathBuf>) {
    let pdfs: Vec<PathBuf> = paths.into_iter().filter(|p| is_pdf(p)).collect();
    if pdfs.is_empty() {
        return;
    }
    OPENED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .extend(pdfs);
    let _ = app.emit("opened-files", ());
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn is_pdf(p: &Path) -> bool {
    p.is_file() && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
}

/// File arguments from a launch, resolved against the launch's folder.
fn file_args(args: impl IntoIterator<Item = String>, cwd: &Path) -> Vec<PathBuf> {
    args.into_iter()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .map(|a| cwd.join(a))
        .collect()
}

#[tauri::command]
fn take_opened_files() -> Vec<PathBuf> {
    std::mem::take(&mut *OPENED.lock().unwrap_or_else(|e| e.into_inner()))
}

/// Card and file work blocks; keep it off the UI thread.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| UiError::with_details("Algo salió mal. Probá de nuevo.", e))?
}

fn main() {
    tauri::Builder::default()
        // Must come first: a second launch (Windows and Linux open each
        // file with a new process) hands its files to the running window
        // and exits.
        .plugin(tauri_plugin_single_instance::init(|app, args, cwd| {
            open_files(app, file_args(args, Path::new(&cwd)));
        }))
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let cwd = std::env::current_dir().unwrap_or_default();
            open_files(app.handle(), file_args(std::env::args(), &cwd));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            card,
            default_output,
            sign,
            take_opened_files,
            verify
        ])
        .build(tauri::generate_context!())
        .expect("error while starting the Gancho window")
        .run(|_app, _event| {
            // macOS hands files over as an event rather than as arguments.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Opened { urls } = _event {
                let paths = urls.iter().filter_map(|u| u.to_file_path().ok());
                open_files(_app, paths);
            }
        });
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
    fn file_arguments_skip_the_program_and_flags() {
        let args = ["gancho-desktop", "-psn_0_12345", "a.pdf", "/tmp/b.pdf"].map(String::from);
        assert_eq!(
            file_args(args, Path::new("/home/ana")),
            [
                PathBuf::from("/home/ana/a.pdf"),
                PathBuf::from("/tmp/b.pdf")
            ]
        );
    }

    #[test]
    fn batch_outputs_must_not_collide() {
        let dir = std::env::temp_dir().join(format!("gancho-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b) = (dir.join("a.pdf"), dir.join("b.pdf"));
        std::fs::write(&a, b"%PDF").unwrap();
        std::fs::write(&b, b"%PDF").unwrap();
        let file = |input: &Path, output: &Path| SignFile {
            input: input.into(),
            output: output.into(),
        };
        let out = dir.join("out.pdf");
        assert!(read_inputs(&[file(&a, &out), file(&b, &out)]).is_err());
        assert!(read_inputs(&[file(&a, &b), file(&b, &out)]).is_err());
        assert_eq!(
            read_inputs(&[file(&a, &out), file(&b, &dir.join("b-firmado.pdf"))])
                .unwrap()
                .len(),
            2
        );
        std::fs::remove_dir_all(dir).unwrap();
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
