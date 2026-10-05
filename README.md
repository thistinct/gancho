# open-gancho

Sign files (PDF first) with the Uruguayan electronic ID card (*cédula de identidad electrónica*), from the command line and a desktop app.

## How the cédula signs

- The chip is a Thales/Gemalto IAS-ECC applet with one **RSA-2048** signing key protected by the user **PIN** (4–8 digits; wrong attempts count down and can block the card).
- Its certificate is issued by **AC Ministerio del Interior**, chained to **AC Raíz Nacional de Uruguay** (AGESIC/UCE).
- Programs reach it through a **PKCS#11** module: the official Thales *Classic Client* (`libgclib.so` / `gclib.dll` / `libgclib.dylib`, downloadable from gub.uy) or OpenSC's new `cedulauy` driver (merged upstream, not yet in a release).
- The card signs SHA-256 digests with PKCS#1 v1.5 padding. We use `CKM_SHA256_RSA_PKCS`, so the module does the hashing.

## Layout

| Crate | Role |
|---|---|
| `gancho-core` | `Signer` trait; will hold CMS/CAdES and PDF/PAdES signing and verification. Has no PKCS#11 dependency, so it is tested with software keys. |
| `gancho-card` | Finds and loads the PKCS#11 module (`cryptoki`), lists cards and certificates, logs in with the PIN, and implements `Signer` for the card. |
| `gancho-cli` | The `gancho` binary. |
| `gancho-desktop` | *(planned)* Tauri 2 app reusing the same crates. |

## Try it

```sh
cargo build
# Optional: point at a specific module, otherwise known install paths are tried
export GANCHO_PKCS11_MODULE=/usr/lib/libgclib.so
./target/debug/gancho devices     # readers with a card
./target/debug/gancho certs       # certificates on the card (no PIN needed)
./target/debug/gancho self-test   # asks for the PIN, signs a test message, verifies it
```

Without a card, SoftHSM2 works as a stand-in (`--module /usr/lib/softhsm/libsofthsm2.so`).

## Roadmap

1. **Card access** (done): `devices`, `certs`, `self-test`.
2. **PDF signing, PAdES-B-B**: incremental update with a signature field, `/ByteRange` placeholder, `/SubFilter /ETSI.CAdES.detached`; detached CMS SignedData with `contentType`, `messageDigest` and `signingCertificateV2` signed attributes (`cms`, `x509-cert`, `lopdf` for parsing).
3. **Verification**: check the CMS signature, the byte range, and the chain against the bundled ACRN and Ministerio del Interior CA certificates.
4. **Timestamps and long-term validation**: optional RFC 3161 TSA (PAdES-B-T), then a DSS dictionary with the chain and CRLs (PAdES-B-LT).
5. **Visible signature** appearance.
6. **Desktop app** (Tauri 2): pick file, show certificate, enter PIN, sign, verify.
7. Packaging per OS, plus CAdES `.p7s` for arbitrary files.
