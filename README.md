# open-gancho

Sign files (PDF first) with the Uruguayan electronic ID card (*cédula de identidad electrónica*), from the command line and a desktop app.

## How the cédula signs

- The chip is a Thales/Gemalto IAS-ECC applet with one **RSA-2048** signing key protected by the user **PIN** (4–8 digits; wrong attempts count down and can block the card).
- Its certificate is issued by **AC Ministerio del Interior**, chained to **AC Raíz Nacional de Uruguay** (AGESIC/UCE).
- By default `gancho` talks to the card **directly** over the operating system's smart-card service (PC/SC), sending the documented IAS-ECC commands (`SELECT → VERIFY → MSE:SET DST → PSO:HASH → PSO:CDS`). No vendor driver is needed: PC/SC is built into macOS and Windows, and on Linux it is the `pcscd` package.
- Alternatively it can go through a **PKCS#11** module: the official Thales *Classic Client* (`libgclib`, from gub.uy) or OpenSC's new `cedulauy` driver (`--backend pkcs11` or `--module PATH`).
- The card signs SHA-256 digests with PKCS#1 v1.5 padding.
- Before sending a PIN, `gancho` reads the retry counter (this costs no try) and refuses to use the last remaining try.

The command sequence follows AGESIC's technical documentation as written up in [firmauy's card protocol notes](https://github.com/carlosplanchon/firmauy/blob/main/docs/card-protocol.md).

## Layout

| Crate | Role |
|---|---|
| `gancho-core` | `Signer` trait; will hold CMS/CAdES and PDF/PAdES signing and verification. Has no PKCS#11 dependency, so it is tested with software keys. |
| `gancho-card` | Card access. `native`: direct PC/SC (`pcsc` crate), tested against a simulated card. `pkcs11`: through an installed module (`cryptoki`). Both implement `Signer`. |
| `gancho-cli` | The `gancho` binary. |
| `gancho-desktop` | *(planned)* Tauri 2 app reusing the same crates. |

## Try it

Install Rust (<https://rustup.rs>), plug in the reader, insert the cédula, then:

```sh
cargo run -p gancho -- devices     # readers and whether a card is inserted
cargo run -p gancho -- certs       # the signing certificate (no PIN needed)
cargo run -p gancho -- self-test   # asks for the PIN, signs a test message, verifies it
```

On Linux, also install `pcscd` and the headers (`libpcsclite-dev` on Debian/Ubuntu).

To use a PKCS#11 driver instead, add `--backend pkcs11` (optionally with `--module PATH` or `GANCHO_PKCS11_MODULE`). Without a card, SoftHSM2 works as a stand-in there (`--module /usr/lib/softhsm/libsofthsm2.so`).

## Roadmap

1. **Card access** (done): `devices`, `certs`, `self-test`, directly or via PKCS#11.
2. **PDF signing, PAdES-B-B**: incremental update with a signature field, `/ByteRange` placeholder, `/SubFilter /ETSI.CAdES.detached`; detached CMS SignedData with `contentType`, `messageDigest` and `signingCertificateV2` signed attributes (`cms`, `x509-cert`, `lopdf` for parsing).
3. **Verification**: check the CMS signature, the byte range, and the chain against the bundled ACRN and Ministerio del Interior CA certificates.
4. **Timestamps and long-term validation**: optional RFC 3161 TSA (PAdES-B-T), then a DSS dictionary with the chain and CRLs (PAdES-B-LT).
5. **Visible signature** appearance.
6. **Desktop app** (Tauri 2): pick file, show certificate, enter PIN, sign, verify.
7. Packaging per OS, plus CAdES `.p7s` for arbitrary files.
