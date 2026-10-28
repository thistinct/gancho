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
| `gancho-core` | `Signer` trait, detached CMS (CAdES) signatures, PAdES-B-B PDF signing and verification, CA path building. Has no card dependency, so it is tested with software keys. |
| `gancho-card` | Card access. `native`: direct PC/SC (`pcsc` crate), tested against a simulated card. `pkcs11`: through an installed module (`cryptoki`). Both implement `Signer`. |
| `gancho-cli` | The `gancho` binary. |
| `gancho-desktop` | Tauri 2 window (plain HTML in `ui/`, logic in Rust): card status, sign with PIN, verify. |

## Try it

Install Rust (<https://rustup.rs>), plug in the reader, insert the cédula, then:

```sh
cargo run -p gancho -- devices     # readers and whether a card is inserted
cargo run -p gancho -- certs       # the signing certificate (no PIN needed)
cargo run -p gancho -- self-test   # asks for the PIN, signs a test message, verifies it
cargo run -p gancho -- sign samples/ejemplo.pdf   # writes samples/ejemplo-firmado.pdf
```

`sign` also takes `-o OUT.pdf`, `--reason "Conformidad"` and `--location "Montevideo"`. The issuing CA certificates are embedded so readers can connect the signer to the national root.

Add `--visible` for a signature box with your name and the date (bottom-left of the last page; `--page N` and `--rect x1,y1,x2,y2` in points move it).

**Signing time.** `--time local` (the default) records this computer's clock; verifiers show it as the time the signer claims. `--time tsa` has a timestamp server certify it instead (PAdES-B-T, needs internet); it uses `http://timestamp.digicert.com` unless `--tsa URL` names another (`--tsa` alone implies `--time tsa`).

**Long-term validity** (optional). `--lt` stores the certificates and their revocation status (an OCSP answer, or the CA's CRL) in the PDF's Document Security Store, so the signature can still be checked after the certificate expires and the CA stops answering for it (PAdES-B-LT together with `--time tsa`). The status of your own certificate is fetched before the card signs: if it is revoked, or the CA cannot be reached, nothing is signed. `gancho ltv FILE.pdf` adds the same data later to a PDF that is already signed, for every signature in it.

**Several signers.** Signing an already signed PDF adds another signature in an incremental update and keeps the earlier ones valid; each signer can choose `--lt` independently. A PDF certified by its author with "no changes allowed" is refused.

```sh
cargo run -p gancho -- verify samples/ejemplo-firmado.pdf   # no card needed
```

`verify` lists every signature, oldest first, and checks each one's integrity, that whatever was added after it is only further signatures and validation data (new page content or a changed annotation fails it), the certificate path up to AC Raíz Nacional, the certificate dates at the signing time, any timestamp, and revocation against the data stored in the PDF (it fetches nothing; a revocation after a certified timestamp does not invalidate the signature). Both commands take `--ca FILE` (DER or PEM, repeatable) for extra CA certificates; a self-signed one passed to `verify` is trusted as a root.

### Desktop app

```sh
cargo run -p gancho-desktop
```

It shows the cédula's holder, validity and PIN tries; signs a chosen PDF (reason, location, visible box optional; the time from the computer's clock or a timestamp server; long-term validity optional) next to the original as `-firmado.pdf`; and verifies signed PDFs. macOS and Windows need nothing extra; Linux also needs `libwebkit2gtk-4.1-dev`. `cargo install tauri-cli` then `cargo tauri build` in `crates/gancho-desktop` makes an installable `.app`/`.dmg`.

On Linux, also install `pcscd` and the headers (`libpcsclite-dev` on Debian/Ubuntu).

To use a PKCS#11 driver instead, add `--backend pkcs11` (optionally with `--module PATH` or `GANCHO_PKCS11_MODULE`). Without a card, SoftHSM2 works as a stand-in there (`--module /usr/lib/softhsm/libsofthsm2.so`).

## Roadmap

1. **Card access** (done): `devices`, `certs`, `self-test`, directly or via PKCS#11.
2. **PDF signing, PAdES-B-B** (done): `sign`. Incremental update with a signature field, `/ByteRange` placeholder, `/SubFilter /ETSI.CAdES.detached`; detached CMS SignedData with `contentType`, `messageDigest` and `signingCertificateV2` signed attributes (`cms`, `x509-cert`, `lopdf`).
3. **Verification** (done): `verify`. Checks the CMS signature, the byte range, and the chain against the bundled ACRN and Ministerio del Interior CA certificates.
4. **Timestamps** (done): `sign --time tsa` (PAdES-B-T). **Long-term validation** (done): `sign --lt`, `ltv` (DSS with certificates, OCSP and CRLs; PAdES-B-LT). Archive timestamps (B-LTA) are not done.
5. **Visible signature** (done): `sign --visible`.
6. **Desktop app** (done, Tauri 2): pick file, show certificate, enter PIN, sign, verify.
7. Packaging per OS, plus CAdES `.p7s` for arbitrary files.
