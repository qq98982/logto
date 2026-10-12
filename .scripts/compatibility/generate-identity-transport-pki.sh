#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ "$#" == 1 && "$1" == /var/tmp/henry-build/* ]] || exit 1
root=$1
[[ -d "$root" && ! -L "$root" && "$(stat -c '%u|%a|%F' "$root")" == "$(id -u)|700|directory" ]] || exit 1
ca=$root/identity-ca.pem; ca_key=$root/identity-ca.key
key=$root/identity-server.key; csr=$root/identity-server.csr; cert=$root/identity-server.pem; ext=$root/identity-server.ext
for path in "$ca" "$ca_key" "$key" "$csr" "$cert" "$ext"; do [[ ! -e "$path" && ! -L "$path" ]] || exit 1; done
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -subj '/CN=Aster Common206 Identity Fixture CA' -keyout "$ca_key" -out "$ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 -subj '/CN=api.pwnedpasswords.com' -keyout "$key" -out "$csr" >/dev/null 2>&1
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' 'subjectAltName=DNS:api.pwnedpasswords.com,DNS:backchannel.aster.test,DNS:api.weixin.qq.com' 'extendedKeyUsage=serverAuth' >"$ext"
openssl x509 -req -days 1 -sha256 -set_serial "0x$(openssl rand -hex 16)" -in "$csr" -CA "$ca" -CAkey "$ca_key" -extfile "$ext" -out "$cert" >/dev/null 2>&1
openssl verify -CAfile "$ca" -verify_hostname api.pwnedpasswords.com "$cert" >/dev/null
openssl verify -CAfile "$ca" -verify_hostname backchannel.aster.test "$cert" >/dev/null
openssl verify -CAfile "$ca" -verify_hostname api.weixin.qq.com "$cert" >/dev/null
chmod 0400 "$ca_key" "$key"; chmod 0444 "$ca" "$cert"; chmod 0600 "$csr" "$ext"
