//! `gancho`: sign files with the Uruguayan electronic ID card.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use gancho_card::native::{self, NativeSigner, PinStatus};
use gancho_card::pkcs11::Module;
use gancho_core::Signer;
use gancho_core::appearance::Appearance;
use gancho_core::ca;
use gancho_core::cades::{DetachedOptions, looks_like_pdf, sign_detached};
use gancho_core::pdf::{SignOptions, sign_pdf_timestamped};
use gancho_core::tsp::{HttpTsa, TimestampAuthority};
use gancho_core::verify::{
    SignatureReport, format_utc, parse_pdf_date, verify_detached, verify_pdf,
};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use x509_cert::Certificate;
use x509_cert::der::{Decode, DecodePem, Encode};

#[derive(Parser)]
#[command(
    version,
    about = "Firmá archivos con tu cédula de identidad electrónica"
)]
struct Cli {
    /// How to reach the card: directly through the system's smart-card
    /// service, or through an installed PKCS#11 driver.
    #[arg(long, global = true, value_enum, default_value_t = Backend::Native)]
    backend: Backend,
    /// PKCS#11 module to use (implies --backend pkcs11; defaults to
    /// $GANCHO_PKCS11_MODULE or a known install path).
    #[arg(long, global = true)]
    module: Option<PathBuf>,
    /// Card reader to use (any part of its name, as shown by `devices`).
    /// By default every reader with a card is tried.
    #[arg(long, global = true)]
    reader: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Backend {
    Native,
    Pkcs11,
}

#[derive(Subcommand)]
enum Command {
    /// List card readers and whether a card is inserted.
    Devices,
    /// Show the signing certificate stored on the card.
    Certs,
    /// Ask for the PIN, sign a test message on the card and verify it.
    SelfTest,
    /// Sign a file with the card. A PDF gets the signature inside it
    /// (PAdES-B-B, as Adobe Reader expects); any other file gets a separate
    /// `.p7s` signature next to it (CAdES-B-B).
    Sign(SignArgs),
    /// Check the signatures in a PDF, or a `.p7s` signature (no card needed).
    Verify(VerifyArgs),
}

#[derive(clap::Args)]
struct VerifyArgs {
    /// Signed PDF, `.p7s` signature, or a file with its `.p7s` next to it.
    input: PathBuf,
    /// The signed file, when checking a `.p7s` (default: the `.p7s` path
    /// without the extension, e.g. `contrato.docx` for `contrato.docx.p7s`).
    #[arg(long, value_name = "FILE")]
    data: Option<PathBuf>,
    /// Extra CA certificate (DER or PEM) to accept; a self-signed one is
    /// trusted as a root. Can be repeated.
    #[arg(long = "ca", value_name = "FILE")]
    cas: Vec<PathBuf>,
}

#[derive(clap::Args)]
struct SignArgs {
    /// File to sign: a PDF, or any other file for a `.p7s` signature.
    input: PathBuf,
    /// Where to write the signed PDF or the `.p7s` (default:
    /// `<name>-firmado.pdf`, or `<file>.p7s`, next to the input).
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Write a separate `.p7s` signature even for a PDF, leaving the PDF
    /// untouched.
    #[arg(long)]
    detached: bool,
    /// Reason shown by PDF readers, e.g. "Conformidad".
    #[arg(long)]
    reason: Option<String>,
    /// Location shown by PDF readers, e.g. "Montevideo".
    #[arg(long)]
    location: Option<String>,
    /// Extra CA certificate (DER or PEM) to embed when it issued the
    /// signer's certificate. Can be repeated.
    #[arg(long = "ca", value_name = "FILE")]
    cas: Vec<PathBuf>,
    /// Draw a visible signature box (bottom-left of the last page unless
    /// --page or --rect say otherwise).
    #[arg(long)]
    visible: bool,
    /// Page for the visible box, counting from 1 (implies --visible).
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..))]
    page: Option<u32>,
    /// Box position in points from the lower-left corner of the page,
    /// as x1,y1,x2,y2 (implies --visible).
    #[arg(long, value_name = "X1,Y1,X2,Y2", value_parser = parse_rect)]
    rect: Option<[f32; 4]>,
    /// RFC 3161 timestamp server to certify the signing time (B-T),
    /// e.g. http://timestamp.digicert.com
    #[arg(long, value_name = "URL")]
    tsa: Option<String>,
}

fn parse_rect(s: &str) -> std::result::Result<[f32; 4], String> {
    let nums: Vec<f32> = s
        .split(',')
        .map(|p| p.trim().parse::<f32>().map_err(|e| format!("{p:?}: {e}")))
        .collect::<std::result::Result<_, _>>()?;
    match nums[..] {
        [x1, y1, x2, y2] if x2 > x1 && y2 > y1 => Ok([x1, y1, x2, y2]),
        [_, _, _, _] => Err("x2 must exceed x1 and y2 must exceed y1".into()),
        _ => Err("expected four numbers: x1,y1,x2,y2".into()),
    }
}

impl SignArgs {
    /// Whether this makes a `.p7s` rather than a signed PDF. Checked
    /// before the PIN is asked for, as are the PDF-only options.
    fn detached(&self, input: &[u8]) -> Result<bool> {
        let detached = self.detached || !looks_like_pdf(input);
        if detached {
            let pdf_only = [
                ("--reason", self.reason.is_some()),
                ("--location", self.location.is_some()),
                ("--visible", self.visible),
                ("--page", self.page.is_some()),
                ("--rect", self.rect.is_some()),
            ];
            if let Some((flag, _)) = pdf_only.iter().find(|(_, set)| *set) {
                bail!("{flag} only applies when signing inside a PDF, not to a .p7s signature");
            }
        }
        Ok(detached)
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Command::Verify(args) = &cli.command {
        return verify(args);
    }
    let backend = if cli.module.is_some() {
        Backend::Pkcs11
    } else {
        cli.backend
    };
    match backend {
        Backend::Native => run_native(cli.command, cli.reader.as_deref()),
        Backend::Pkcs11 => {
            if cli.reader.is_some() {
                bail!("--reader only works with the native backend");
            }
            run_pkcs11(cli.command, cli.module)
        }
    }
}

fn run_native(command: Command, reader: Option<&str>) -> Result<()> {
    match command {
        Command::Devices => {
            let readers = native::readers()?;
            if readers.is_empty() {
                bail!("no smart card reader found; is the reader plugged in?");
            }
            for r in readers {
                let state = match (r.has_card, r.looks_like_cedula()) {
                    (false, _) => "empty".to_owned(),
                    (true, true) => format!("cédula, ATR {}", hex(&r.atr)),
                    (true, false) => format!("card inserted, ATR {}", hex(&r.atr)),
                };
                println!("{}  ({state})", r.name.to_string_lossy());
            }
        }
        Command::Certs => {
            let mut card = native::connect(reader)?;
            print_certificate(None, &card.certificate()?)?;
        }
        Command::SelfTest => self_test(&mut native_signer(reader)?)?,
        Command::Sign(args) => {
            // Read the file before asking for the PIN so a typo in the path
            // doesn't cost a PIN entry.
            let input = read_file(&args.input)?;
            args.detached(&input)?;
            sign_file(&mut native_signer(reader)?, &args, &input)?;
        }
        Command::Verify(_) => unreachable!("handled before connecting"),
    }
    Ok(())
}

fn run_pkcs11(command: Command, module_path: Option<PathBuf>) -> Result<()> {
    let module = match &module_path {
        Some(p) => Module::load(p),
        None => Module::load_default(),
    }
    .context("loading PKCS#11 module")?;

    match command {
        Command::Devices => {
            let tokens = module.tokens()?;
            if tokens.is_empty() {
                bail!("no card found; is it inserted in the reader?");
            }
            for t in tokens {
                println!(
                    "{}  {} ({} {}) serial {}",
                    t.slot, t.label, t.manufacturer, t.model, t.serial
                );
            }
        }
        Command::Certs => {
            let slot = module.first_token()?;
            for cred in module.certificates(slot)? {
                print_certificate(Some(&cred.label), &cred.certificate_der)?;
            }
        }
        Command::SelfTest => {
            let slot = module.first_token()?;
            let pin = rpassword::prompt_password("PIN: ")?;
            let mut signer = module.signer(slot, pin.into())?;
            self_test(&mut signer)?;
        }
        Command::Sign(args) => {
            let input = read_file(&args.input)?;
            args.detached(&input)?;
            let slot = module.first_token()?;
            let pin = rpassword::prompt_password("PIN: ")?;
            let mut signer = module.signer(slot, pin.into())?;
            sign_file(&mut signer, &args, &input)?;
        }
        Command::Verify(_) => unreachable!("handled before loading the module"),
    }
    Ok(())
}

/// Connects to the cédula, shows the PIN tries left and asks for the PIN.
fn native_signer(reader: Option<&str>) -> Result<NativeSigner<native::PcscTransport>> {
    let mut card = native::connect(reader)?;
    match card.pin_status()? {
        PinStatus::TriesLeft(n) => eprintln!("PIN tries left: {n}"),
        PinStatus::Blocked => bail!("the PIN is blocked"),
        PinStatus::Verified => {}
    }
    let pin = rpassword::prompt_password("PIN: ")?;
    Ok(NativeSigner::new(card, &pin)?)
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn sign_file(signer: &mut dyn Signer, args: &SignArgs, input: &[u8]) -> Result<()> {
    let detached = args.detached(input)?;
    let output = match &args.output {
        Some(p) => p.clone(),
        None if detached => p7s_path(&args.input),
        None => default_output(&args.input),
    };
    let extra = read_certificates(&args.cas)?;
    let mut pool: Vec<&[u8]> = ca::BUNDLED.to_vec();
    pool.extend(extra.iter().map(Vec::as_slice));
    let chain = ca::issuer_chain(signer.certificate_der(), &pool);
    if chain.is_empty() {
        eprintln!(
            "note: the issuing CA certificate is not available, so the signer may show as unverified"
        );
    }
    let mut tsa = args.tsa.clone().map(HttpTsa);
    let tsa = tsa.as_mut().map(|t| t as &mut dyn TimestampAuthority);
    if detached {
        let options = DetachedOptions {
            chain,
            ..Default::default()
        };
        let p7s = sign_detached(input, signer, &options, tsa)
            .with_context(|| format!("signing {}", args.input.display()))?;
        std::fs::write(&output, p7s).with_context(|| format!("writing {}", output.display()))?;
        println!("signature: {}", output.display());
        return Ok(());
    }
    let options = SignOptions {
        reason: args.reason.clone(),
        location: args.location.clone(),
        chain,
        appearance: (args.visible || args.page.is_some() || args.rect.is_some()).then_some(
            Appearance {
                page: args.page,
                rect: args.rect,
            },
        ),
        ..Default::default()
    };
    let signed = sign_pdf_timestamped(input, signer, &options, tsa)
        .with_context(|| format!("signing {}", args.input.display()))?;
    std::fs::write(&output, signed).with_context(|| format!("writing {}", output.display()))?;
    println!("signed: {}", output.display());
    Ok(())
}

fn verify(args: &VerifyArgs) -> Result<()> {
    let input = read_file(&args.input)?;
    let extra = read_certificates(&args.cas)?;
    let anchors: Vec<&[u8]> = extra
        .iter()
        .map(Vec::as_slice)
        .filter(|der| ca::is_root(der))
        .collect();
    let mut cas: Vec<&[u8]> = extra.iter().map(Vec::as_slice).collect();
    cas.retain(|c| !anchors.contains(c));
    if args.data.is_some() || !looks_like_pdf(&input) {
        return verify_p7s(args, input, &anchors, &cas);
    }
    let reports = verify_pdf(&input, &anchors, &cas)?;
    // A PDF without signatures inside may have a `.p7s` next to it.
    if reports.is_empty() && p7s_path(&args.input).is_file() {
        return verify_p7s(args, input, &anchors, &cas);
    }
    if reports.is_empty() {
        bail!("{} has no signatures", args.input.display());
    }
    for (i, r) in reports.iter().enumerate() {
        let title = format!(
            "signature {}: {}",
            i + 1,
            r.field.as_deref().unwrap_or("(unnamed field)")
        );
        print_report(&title, r, true);
    }
    let bad = reports.iter().filter(|r| !r.is_valid()).count();
    if bad > 0 {
        bail!(
            "{bad} of {} signatures did not fully validate",
            reports.len()
        );
    }
    match reports.len() {
        1 => println!("the signature is valid"),
        n => println!("all {n} signatures are valid"),
    }
    Ok(())
}

/// Checks a detached signature. `input` is either the `.p7s` or the signed
/// file with its `.p7s` next to it.
fn verify_p7s(args: &VerifyArgs, input: Vec<u8>, anchors: &[&[u8]], cas: &[&[u8]]) -> Result<()> {
    let sidecar = p7s_path(&args.input);
    let is_signature = args.input.extension().is_some_and(|e| {
        ["p7s", "p7m", "p7b", "sig"].contains(&e.to_string_lossy().to_lowercase().as_str())
    });
    let (sig_path, signature, data_path) = if args.data.is_none() && sidecar.is_file() {
        (
            sidecar.clone(),
            read_file(&sidecar)?,
            Some(args.input.clone()),
        )
    } else if args.data.is_none() && !is_signature {
        bail!(
            "{} is not a PDF and there is no {} next to it; pass the signature file",
            args.input.display(),
            sidecar.display()
        );
    } else {
        let data = args.data.clone().or_else(|| {
            let stripped = args.input.with_extension("");
            (stripped != args.input && stripped.is_file()).then_some(stripped)
        });
        (args.input.clone(), input, data)
    };
    let data = data_path.as_deref().map(read_file).transpose()?;
    let report = verify_detached(&signature, data.as_deref(), anchors, cas).map_err(|e| {
        anyhow::anyhow!(
            "{e} (checking {}; pass the signed file with --data)",
            sig_path.display()
        )
    })?;
    let title = match &data_path {
        Some(d) => format!("signature {} over {}", sig_path.display(), d.display()),
        None => format!("signature {} (file included)", sig_path.display()),
    };
    print_report(&title, &report, false);
    if !report.is_valid() {
        bail!("the signature did not fully validate");
    }
    println!("the signature is valid");
    Ok(())
}

/// Prints one signature's findings. `in_pdf` adds what only applies to
/// signatures inside a PDF.
fn print_report(title: &str, r: &SignatureReport, in_pdf: bool) {
    let mark = |ok: bool| if ok { "ok" } else { "FAIL" };
    println!("{title}");
    if let Some(s) = &r.signer {
        println!("  signer:    {s}");
    }
    if let Some(t) = &r.signed_at {
        let shown = parse_pdf_date(t).map_or_else(|| t.clone(), format_utc);
        println!("  time:      {shown} (claimed by the signer)");
    }
    if let Some(x) = &r.reason {
        println!("  reason:    {x}");
    }
    if let Some(x) = &r.location {
        println!("  location:  {x}");
    }
    match &r.integrity {
        Ok(()) => println!("  integrity: ok"),
        Err(e) => println!("  integrity: FAIL, {e}"),
    }
    if r.integrity.is_ok() && in_pdf {
        println!(
            "  coverage:  {}",
            if r.covers_whole_file {
                "whole document"
            } else {
                "the document was extended after this signature (e.g. another signature)"
            }
        );
    }
    if r.integrity.is_ok() {
        for c in &r.chain {
            println!("  issued by: {c}");
        }
        println!(
            "  trust:     {}",
            if r.trusted {
                "ok, chains to a trusted root"
            } else {
                "FAIL, no path to a trusted root"
            }
        );
        if let Some(ts) = &r.timestamp {
            match &ts.integrity {
                Ok(()) => println!(
                    "  timestamp: {} by {}, {}",
                    ts.time.map_or_else(|| "?".into(), format_utc),
                    ts.tsa.as_deref().unwrap_or("?"),
                    if ts.trusted {
                        "trusted"
                    } else {
                        "authority not trusted"
                    }
                ),
                Err(e) => println!("  timestamp: FAIL, {e}"),
            }
        }
        match r.valid_at_signing_time {
            Some(ok) => println!("  dates:     {}", mark(ok)),
            None => println!("  dates:     unknown (no signing time)"),
        }
    }
    println!();
}

/// Reads certificates given as DER or PEM files.
fn read_certificates(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    paths
        .iter()
        .map(|p| {
            let bytes = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
            let cert = if bytes.starts_with(b"-----BEGIN") {
                Certificate::from_pem(&bytes)
            } else {
                Certificate::from_der(&bytes)
            }
            .with_context(|| format!("{} is not an X.509 certificate", p.display()))?;
            Ok(cert.to_der()?)
        })
        .collect()
}

/// `contrato.docx` → `contrato.docx.p7s`, in the same folder.
fn p7s_path(input: &Path) -> PathBuf {
    let mut name = input.as_os_str().to_owned();
    name.push(".p7s");
    PathBuf::from(name)
}

/// `contrato.pdf` → `contrato-firmado.pdf`, in the same folder.
fn default_output(input: &Path) -> PathBuf {
    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
    input.with_file_name(format!("{stem}-firmado.pdf"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn print_certificate(label: Option<&str>, der: &[u8]) -> Result<()> {
    let cert = Certificate::from_der(der)?;
    let tbs = cert.tbs_certificate();
    if let Some(label) = label {
        println!("label:   {label}");
    }
    println!("subject: {}", tbs.subject());
    println!("issuer:  {}", tbs.issuer());
    println!(
        "valid:   {} .. {}",
        tbs.validity().not_before,
        tbs.validity().not_after
    );
    println!();
    Ok(())
}

/// Signs a fixed message and checks the signature against the card's certificate.
fn self_test(signer: &mut impl Signer) -> Result<()> {
    let msg = b"open-gancho self-test";
    let sig = signer.sign_sha256_rsa(msg)?;

    let cert = Certificate::from_der(signer.certificate_der())?;
    let spki = cert.tbs_certificate().subject_public_key_info().to_der()?;
    let key = VerifyingKey::<sha2::Sha256>::new(rsa::RsaPublicKey::from_public_key_der(&spki)?);
    key.verify(msg, &Signature::try_from(sig.as_slice())?)
        .context("card signature did not verify against its certificate")?;
    println!(
        "OK: signed as {} ({} byte signature) and verified",
        cert.tbs_certificate().subject(),
        sig.len()
    );
    Ok(())
}
