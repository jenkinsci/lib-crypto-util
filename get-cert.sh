#!/bin/bash
set -euo pipefail

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

cat >"$tmpdir/root.cnf" <<'EOF'
[ req ]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[ dn ]
CN = lib-crypto-util Test Root CA
O = Jenkins CI
C = US
[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
EOF

cat >"$tmpdir/int.cnf" <<'EOF'
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = lib-crypto-util Test Intermediate CA
O = Jenkins CI
C = US
[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
EOF

cat >"$tmpdir/leaf.cnf" <<'EOF'
[ req ]
distinguished_name = dn
req_extensions = v3_req
prompt = no
[ dn ]
CN = www.google.com
O = Jenkins CI
C = US
[ v3_req ]
subjectAltName = @alt_names
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
[ alt_names ]
DNS.1 = www.google.com
EOF

openssl genrsa -out "$tmpdir/root.key" 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "$tmpdir/root.key" -sha256 -days 3650 -out "$tmpdir/verisign.crt" -config "$tmpdir/root.cnf" >/dev/null 2>&1

openssl genrsa -out "$tmpdir/int.key" 2048 >/dev/null 2>&1
openssl req -new -key "$tmpdir/int.key" -out "$tmpdir/int.csr" -config "$tmpdir/int.cnf" >/dev/null 2>&1
openssl x509 -req -in "$tmpdir/int.csr" -CA "$tmpdir/verisign.crt" -CAkey "$tmpdir/root.key" -CAcreateserial -out "$tmpdir/sun.crt" -days 3650 -sha256 -extfile "$tmpdir/int.cnf" -extensions v3_intermediate_ca >/dev/null 2>&1

openssl genrsa -out "$tmpdir/leaf.key" 2048 >/dev/null 2>&1
openssl req -new -key "$tmpdir/leaf.key" -out "$tmpdir/leaf.csr" -config "$tmpdir/leaf.cnf" >/dev/null 2>&1
openssl x509 -req -in "$tmpdir/leaf.csr" -CA "$tmpdir/sun.crt" -CAkey "$tmpdir/int.key" -CAcreateserial -out "$tmpdir/site.crt" -days 825 -sha256 -extfile "$tmpdir/leaf.cnf" -extensions v3_req >/dev/null 2>&1

cat "$tmpdir/site.crt"
printf '\n'
cat "$tmpdir/sun.crt"
printf '\n'
cat "$tmpdir/verisign.crt"
