//! `gancho`: sign files with the Uruguayan electronic ID card.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use gancho_card::native::{self, NativeSigner, PinStatus};
use gancho_card::pkcs11::Module;
use gancho_core::Signer;
use gancho_core::pdf::{SignOptions, sign_pdf};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

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
    /// Sign a PDF with the card (PAdES-B-B, as Adobe Reader expects).
    Sign(SignArgs),
}

#[derive(clap::Args)]
struct SignArgs {
    /// PDF to sign.
    input: PathBuf,
    /// Where to write the signed PDF (default: `<name>-firmado.pdf` next
    /// to the input).
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Reason shown by PDF readers, e.g. "Conformidad".
    #[arg(long)]
    reason: Option<String>,
    /// Location shown by PDF readers, e.g. "Montevideo".
    #[arg(long)]
    location: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
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
            // Read the PDF before asking for the PIN so a typo in the path
            // doesn't cost a PIN entry.
            let input = read_pdf(&args.input)?;
            sign_file(&mut native_signer(reader)?, &args, &input)?;
        }
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
            let input = read_pdf(&args.input)?;
            let slot = module.first_token()?;
            let pin = rpassword::prompt_password("PIN: ")?;
            let mut signer = module.signer(slot, pin.into())?;
            sign_file(&mut signer, &args, &input)?;
        }
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

fn read_pdf(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn sign_file(signer: &mut dyn Signer, args: &SignArgs, input: &[u8]) -> Result<()> {
    let output = match &args.output {
        Some(p) => p.clone(),
        None => default_output(&args.input),
    };
    let options = SignOptions {
        reason: args.reason.clone(),
        location: args.location.clone(),
        ..Default::default()
    };
    let signed = sign_pdf(input, signer, &options)
        .with_context(|| format!("signing {}", args.input.display()))?;
    std::fs::write(&output, signed).with_context(|| format!("writing {}", output.display()))?;
    println!("signed: {}", output.display());
    Ok(())
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
