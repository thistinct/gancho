//! `gancho`: sign files with the Uruguayan electronic ID card.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use gancho_card::native::{self, NativeSigner, PinStatus};
use gancho_card::pkcs11::Module;
use gancho_core::Signer;
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let backend = if cli.module.is_some() {
        Backend::Pkcs11
    } else {
        cli.backend
    };
    match backend {
        Backend::Native => run_native(cli.command),
        Backend::Pkcs11 => run_pkcs11(cli.command, cli.module),
    }
}

fn run_native(command: Command) -> Result<()> {
    match command {
        Command::Devices => {
            let readers = native::readers()?;
            if readers.is_empty() {
                bail!("no smart card reader found; is the reader plugged in?");
            }
            for r in readers {
                let state = if r.has_card { "card inserted" } else { "empty" };
                println!("{}  ({state})", r.name.to_string_lossy());
            }
        }
        Command::Certs => {
            let mut card = native::connect(None)?;
            print_certificate(None, &card.certificate()?)?;
        }
        Command::SelfTest => {
            let mut card = native::connect(None)?;
            match card.pin_status()? {
                PinStatus::TriesLeft(n) => eprintln!("PIN tries left: {n}"),
                PinStatus::Blocked => bail!("the PIN is blocked"),
                PinStatus::Verified => {}
            }
            let pin = rpassword::prompt_password("PIN: ")?;
            let mut signer = NativeSigner::new(card, &pin)?;
            self_test(&mut signer)?;
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
    }
    Ok(())
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
