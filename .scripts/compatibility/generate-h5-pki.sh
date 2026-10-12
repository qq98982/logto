#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

[[ "$#" == 2 && "$1" == generate && "$2" == /var/tmp/henry-build/* ]] || exit 1
readonly directory="$2"
[[ -d "$directory" && ! -L "$directory" \
  && "$(stat -c '%u|%a|%F' -- "$directory")" == "$(id -u)|700|directory" ]] || exit 1
readonly ca="$directory/h5-loopback-ca.pem"
readonly ca_key="$directory/h5-loopback-ca.key"
readonly key="$directory/h5-loopback-server.key"
readonly csr="$directory/h5-loopback-server.csr"
readonly cert="$directory/h5-loopback-server.pem"
readonly ext="$directory/h5-loopback-server.ext"
readonly spki="$directory/h5-loopback-server.spki"
for file in "$ca" "$ca_key" "$key" "$csr" "$cert" "$ext" "$spki"; do
  [[ ! -e "$file" && ! -L "$file" ]] || exit 1
done

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -subj '/CN=Aster H5 Loopback CA' -keyout "$ca_key" -out "$ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 -subj '/CN=localhost' \
  -keyout "$key" -out "$csr" >/dev/null 2>&1
printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature,keyEncipherment' \
  'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  'extendedKeyUsage=serverAuth' >"$ext"
openssl x509 -req -days 1 -sha256 -set_serial "0x$(openssl rand -hex 16)" \
  -in "$csr" -CA "$ca" -CAkey "$ca_key" -extfile "$ext" -out "$cert" >/dev/null 2>&1
openssl verify -CAfile "$ca" -verify_hostname localhost "$cert" >/dev/null 2>&1
openssl x509 -in "$cert" -pubkey -noout \
  | openssl pkey -pubin -outform DER 2>/dev/null \
  | openssl dgst -sha256 -binary \
  | openssl base64 -A >"$spki"
[[ "$(cat "$spki")" =~ ^[A-Za-z0-9+/]{43}=$ ]]
chmod 0600 "$ca_key" "$key" "$csr" "$cert" "$ext"
chmod 0400 "$ca" "$spki"
printf 'h5-loopback-pki-ready\n'
