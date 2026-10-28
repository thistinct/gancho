#!/bin/sh
# Regenerates the test PKI for the long-term validation tests: a root, an
# issuing CA, a signer whose certificate points at a CRL and an OCSP
# responder, a second signer that is revoked, and the CRLs. The OCSP
# answers are made at test time with `openssl ocsp` from ca-index.txt.
set -e
cd "$(dirname "$0")"
rm -f *.pem *.der *.crl *.txt* *.srl *.attr* *.old crlnumber* openssl.cnf
cat > openssl.cnf <<'CNF'
[ca]
default_ca = ca
[ca]
database = ./ca-index.txt
crlnumber = ./crlnumber
default_md = sha256
default_crl_days = 36500
[root_ext]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ca_ext]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
crlDistributionPoints = URI:http://pki.test/root.crl
[leaf_ext]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, nonRepudiation
crlDistributionPoints = URI:http://pki.test/ca.crl
authorityInfoAccess = OCSP;URI:http://ocsp.pki.test/
[crl_only_ext]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, nonRepudiation
crlDistributionPoints = URI:http://pki.test/ca.crl
CNF
key() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" 2>/dev/null; }
key root-key.pem; key ca-key.pem; key leaf-key.pem; key revoked-key.pem; key crl-only-key.pem
openssl req -x509 -new -key root-key.pem -subj "/CN=LTV Test Root/C=UY" -days 36500 \
  -config openssl.cnf -extensions root_ext -set_serial 1 -out root.pem
openssl req -new -key ca-key.pem -subj "/CN=LTV Test CA/C=UY" -out ca.csr
openssl x509 -req -in ca.csr -CA root.pem -CAkey root-key.pem -set_serial 2 -days 36500 \
  -extfile openssl.cnf -extensions ca_ext -out ca.pem
for n in leaf:16 revoked:17 crl-only:18; do
  name=${n%%:*}; serial=${n##*:}
  ext=leaf_ext; [ "$name" = crl-only ] && ext=crl_only_ext
  openssl req -new -key $name-key.pem -subj "/CN=LTV Test ${name}/C=UY" -out $name.csr
  openssl x509 -req -in $name.csr -CA ca.pem -CAkey ca-key.pem -set_serial $serial \
    -days 36500 -extfile openssl.cnf -extensions $ext -out $name.pem
done
rm -f *.csr
# CA database: everything valid except "revoked".
: > ca-index.txt
for f in leaf revoked crl-only; do
  serial=$(openssl x509 -in $f.pem -noout -serial | cut -d= -f2)
  end=$(openssl x509 -in $f.pem -noout -enddate | cut -d= -f2)
  enddate=$(date -u -d "$end" +%Y%m%d%H%M%SZ)
  subj=$(openssl x509 -in $f.pem -noout -subject -nameopt compat | sed 's/^subject=//')
  printf 'V\t%s\t\t%s\tunknown\t%s\n' "$enddate" "$serial" "$subj" >> ca-index.txt
done
echo 01 > crlnumber
openssl ca -config openssl.cnf -revoke revoked.pem -keyfile ca-key.pem -cert ca.pem \
  -crl_reason keyCompromise 2>/dev/null
openssl ca -config openssl.cnf -gencrl -keyfile ca-key.pem -cert ca.pem -out ca-crl.pem 2>/dev/null
openssl crl -in ca-crl.pem -outform der -out ca.crl
: > root-index.txt
cp openssl.cnf root.cnf
sed -i 's#./ca-index.txt#./root-index.txt#' root.cnf
openssl ca -config root.cnf -gencrl -keyfile root-key.pem -cert root.pem -out root-crl.pem 2>/dev/null
openssl crl -in root-crl.pem -outform der -out root.crl
rm -f ca-crl.pem root-crl.pem root.cnf root-index.txt* crlnumber* ca-index.txt.attr* ca-index.txt.old
for f in root ca leaf revoked crl-only; do openssl x509 -in $f.pem -outform der -out $f.der; done
