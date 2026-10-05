//! `gancho`: sign files with the Uruguayan electronic ID card.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use gancho_card::Module;
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
    /// PKCS#11 module to use (defaults to $GANCHO_PKCS11_MODULE or a known install path).
    #[arg(long, global = true)]
    module: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List readers with a card inserted.
    Devices,
    /// Show the certificates stored on the card.
    Certs,
    /// Ask for the PIN, sign a test message on the card and verify it.
    SelfTest,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let module = match &cli.module {
        Some(p) => Module::load(p),
        None => Module::load_default(),
    }
    .context("loading PKCS#11 module")?;

    match cli.command {
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
                let cert = Certificate::from_der(&cred.certificate_der)?;
                let tbs = &cert.tbs_certificate();
                println!("label:   {}", cred.label);
                println!("subject: {}", tbs.subject());
                println!("issuer:  {}", tbs.issuer());
                println!(
                    "valid:   {} .. {}",
                    tbs.validity().not_before,
                    tbs.validity().not_after
                );
                println!();
            }
        }
        Command::SelfTest => {
            let slot = module.first_token()?;
            let pin = rpassword::prompt_password("PIN: ")?;
            let mut signer = module.signer(slot, pin.into())?;
            let msg = b"open-gancho self-test";
            let sig = signer.sign_sha256_rsa(msg)?;

            let cert = Certificate::from_der(signer.certificate_der())?;
            let spki = cert.tbs_certificate().subject_public_key_info().to_der()?;
            let key =
                VerifyingKey::<sha2::Sha256>::new(rsa::RsaPublicKey::from_public_key_der(&spki)?);
            key.verify(msg, &Signature::try_from(sig.as_slice())?)
                .context("card signature did not verify against its certificate")?;
            println!(
                "OK: signed with \"{}\" ({} byte signature) and verified",
                signer.credential().label,
                sig.len()
            );
        }
    }
    Ok(())
}
