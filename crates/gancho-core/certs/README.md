# Bundled CA certificates

| File | Subject | Valid until | SHA-256 fingerprint |
|---|---|---|---|
| `acrn.der` | Autoridad Certificadora Raíz Nacional de Uruguay (AGESIC), self-signed root | 2031-10-29 | `55:33:A0:40:1F:61:2C:68:8E:BC:E5:BF:53:F2:EC:14:A7:34:EB:17:8B:FA:E0:0E:50:E8:5D:AE:67:23:07:8A` |
| `mica.der` | Autoridad Certificadora del Ministerio del Interior, issued by the root above; issues cédula certificates | 2031-10-27 | `A2:9C:AD:5C:89:AA:49:CF:F8:1F:17:F4:5C:42:FD:44:68:55:10:24:6D:9A:B5:D0:31:44:8E:2F:DA:25:17:BE` |

Sources: <https://www.uce.gub.uy/acrn/acrn.cer> and <https://ca.minterior.gub.uy/certificados/MICA.cer>. Check the fingerprints against those before replacing either file.
