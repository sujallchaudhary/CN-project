#!/usr/bin/env bash
# Generates every certificate the lab needs, with OpenSSL.
#
#  certs/server.key + server.crt   self-signed, RSA-2048, SAN localhost/127.0.0.1   (the main HTTPS server, port 4433)
#  certs/ca.crt + ca.key           a small local Certificate Authority
#  certs/lab/valid.*               signed by the CA, valid                           (cert lab, port 4441)
#  certs/lab/expired.*             signed by the CA, but expired in 2023             (cert lab, port 4442)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }
echo "Using $(openssl version)"
rm -rf server.key server.crt ca.key ca.crt lab .ca-db
mkdir -p lab

# ---- 1. Self-signed server certificate (exactly the command from the project brief) ----
openssl req -x509 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

# ---- 2. Local CA ----
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 3650 -nodes \
  -subj "/O=Secure Web Server Lab/CN=Lab Root CA" \
  -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# 'openssl ca' is used (rather than 'openssl x509 -req') because it can back-date a certificate on every OpenSSL 3.x.
mkdir .ca-db .ca-db/newcerts; : > .ca-db/index.txt; echo 1000 > .ca-db/serial
cat > .ca-db/ca.cnf <<CNF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = $PWD/.ca-db
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
serial = \$dir/serial
certificate = $PWD/ca.crt
private_key = $PWD/ca.key
default_md = sha256
policy = pol
unique_subject = no
copy_extensions = none
[ pol ]
commonName = supplied
[ leaf ]
basicConstraints = CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = \$ENV::SAN
CNF

issue() { # name CN SAN [extra 'openssl ca' args]
  local name="$1" cn="$2" san="$3"; shift 3
  openssl req -newkey rsa:2048 -nodes -keyout "lab/$name.key" -subj "/CN=$cn" -out ".ca-db/$name.csr" 2>/dev/null
  SAN="$san" openssl ca -config .ca-db/ca.cnf -batch -notext -extensions leaf -days 365 \
    -in ".ca-db/$name.csr" -out "lab/$name.crt" "$@" 2>/dev/null
}
issue valid     localhost     "DNS:localhost,IP:127.0.0.1"
issue expired   localhost     "DNS:localhost,IP:127.0.0.1" -startdate 20230101000000Z -enddate 20230102000000Z
rm -rf .ca-db
chmod 600 server.key ca.key lab/*.key

echo
echo "Done:"
for f in server.crt lab/valid.crt lab/expired.crt; do
  printf '  %-18s %s\n' "$f" "$(openssl x509 -in $f -noout -subject -enddate | tr '\n' ' ')"
done
