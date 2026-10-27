//! Gancho desktop: pick a PDF, enter the PIN, sign it with the cédula;
//! or check the signatures in a PDF. The window is plain HTML in `ui/`;
//! everything that touches the card or the file runs here.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};

use gancho_card::native::{self, NativeSigner, PinStatus};
use gancho_core::Signer;
use gancho_core::appearance::Appearance;
use gancho_core::ca::{self, CertificateSummary};
use gancho_core::pdf::{SignOptions, sign_pdf_timestamped};
use gancho_core::tsp::{HttpTsa, TimestampAuthority};
use gancho_core::verify::{SignatureReport, format_utc, parse_pdf_date, verify_pdf};
use serde::{Deserialize, Serialize};

/// Errors cross to the window as their message.
type Result<T> = std::result::Result<T, String>;

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
        let readers = native::readers().map_err(|e| e.to_string())?;
        let mut card = native::connect(None).map_err(|e| e.to_string())?;
        let der = card.certificate().map_err(|e| e.to_string())?;
        let summary = ca::summarize(&der).ok_or("no se pudo leer el certificado de la cédula")?;
        let (pin_tries, pin_blocked) = match card.pin_status().map_err(|e| e.to_string())? {
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
async fn sign(request: SignRequest) -> Result<PathBuf> {
    blocking(move || {
        // Checked before the PIN is used.
        if same_file(&request.input, &request.output) {
            return Err("elegí otro nombre: el original no se sobrescribe".into());
        }
        let input = std::fs::read(&request.input)
            .map_err(|e| format!("reading {}: {e}", request.input.display()))?;
        let card = native::connect(None).map_err(|e| e.to_string())?;
        let mut signer = NativeSigner::new(card, &request.pin).map_err(|e| e.to_string())?;
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
        let signed = sign_pdf_timestamped(&input, &mut signer, &options, tsa)
            .map_err(|e| e.to_string())?;
        std::fs::write(&request.output, signed)
            .map_err(|e| format!("writing {}: {e}", request.output.display()))?;
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

#[tauri::command]
async fn verify(path: PathBuf) -> Result<Vec<Check>> {
    blocking(move || {
        let pdf = std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        let reports = verify_pdf(&pdf, &[], &[]).map_err(|e| e.to_string())?;
        Ok(reports.iter().map(check_view).collect())
    })
    .await
}

fn check_view(r: &SignatureReport) -> Check {
    let mut notes = Vec::new();
    let mut note = |ok: bool, text: String| notes.push(Note { ok, text });
    match &r.integrity {
        Ok(()) => note(true, "El documento no fue modificado desde que se firmó.".into()),
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
            note(true, "El certificado encadena a la raíz nacional de Uruguay.".into());
        } else {
            note(false, "El certificado no encadena a una raíz de confianza.".into());
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
                        if trusted { "." } else { " (autoridad no confiable)." }
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
        .map_err(|e| e.to_string())?
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![card, default_output, sign, verify])
        .run(tauri::generate_context!())
        .expect("error while running the Gancho window");
}
