#!/bin/sh
# Checks that oqsprovider is loaded and ML-DSA works end to end:
# keygen -> self-signed cert -> verify -> sign/verify data, for ML-DSA-44/65/87,
# plus one oqsprovider hybrid. Prints which provider serves each algorithm:
# on OpenSSL >= 3.5 pure ML-DSA is native (@ default) and oqsprovider adds the hybrids.
# Runs at image build time; also usable in CI:  docker run --rm pqca/oqs-base:dev oqs-selftest
set -eu

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

openssl version
openssl list -providers -provider oqsprovider | grep -q 'oqsprovider' \
  || { echo "FAIL: oqsprovider not loaded" >&2; exit 1; }

algs="$(openssl list -signature-algorithms -provider oqsprovider)"

# name:OID:last OID byte (RFC 9881 / FIPS 204). DER of 2.16.840.1.101.3.4.3.x is 0609 6086480165030403 <x>.
for entry in mldsa44:2.16.840.1.101.3.4.3.17:11 mldsa65:2.16.840.1.101.3.4.3.18:12 mldsa87:2.16.840.1.101.3.4.3.19:13; do
  alg="${entry%%:*}"; rest="${entry#*:}"; oid="${rest%%:*}"; oid_der="06096086480165030403${rest#*:}"
  # Exact name only; a plain substring match would also hit hybrids like p384_mldsa65.
  line="$(echo "$algs" | grep -Ei "(^|[ ,{])${alg}([ ,}]|$)" | head -n1)" \
    || { echo "FAIL: $alg not listed" >&2; exit 1; }
  provider="${line##*@ }"

  openssl genpkey -algorithm "$alg" -out "$work/$alg.key"
  openssl req -x509 -new -key "$work/$alg.key" -subj "/CN=oqs-selftest $alg" -days 1 -outform DER -out "$work/$alg.der"
  openssl x509 -inform DER -in "$work/$alg.der" -out "$work/$alg.crt"
  openssl verify -CAfile "$work/$alg.crt" "$work/$alg.crt" >/dev/null
  od -An -v -tx1 "$work/$alg.der" | tr -d ' \n' | grep -q "$oid_der" \
    || { echo "FAIL: $alg cert does not carry OID $oid" >&2; exit 1; }

  printf 'pqca' > "$work/msg"
  openssl pkeyutl -sign -inkey "$work/$alg.key" -in "$work/msg" -rawin -out "$work/sig"
  openssl pkeyutl -verify -inkey "$work/$alg.key" -in "$work/msg" -rawin -sigfile "$work/sig" >/dev/null

  echo "OK: $alg @ $provider (OID $oid, sig $(wc -c < "$work/sig") bytes)"
done

# oqsprovider must actually work, not just load.
hybrid=p384_mldsa65
echo "$algs" | grep -Eq "(^|[ ,{])${hybrid} @ oqsprovider" || { echo "FAIL: $hybrid not served by oqsprovider" >&2; exit 1; }
openssl genpkey -algorithm "$hybrid" -propquery provider=oqsprovider -out "$work/hybrid.key"
openssl req -x509 -new -key "$work/hybrid.key" -subj "/CN=oqs-selftest $hybrid" -days 1 -out "$work/hybrid.crt"
openssl verify -CAfile "$work/hybrid.crt" "$work/hybrid.crt" >/dev/null
echo "OK: $hybrid @ oqsprovider"

echo "oqs-selftest passed"
