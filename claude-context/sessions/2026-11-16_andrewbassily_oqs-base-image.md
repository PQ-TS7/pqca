# 2026-11-16 — OQS base image

**Author:** andrewbassily  
**Area:** images/oqs-base

## Goal
Docker base image with compiled OpenSSL 3.x + liboqs + oqs-provider, ML-DSA-65 support.

## Done
- `images/oqs-base/Dockerfile`: multi-stage on `debian:trixie-slim`. Builder compiles OpenSSL 3.5.9 (LTS) into `/opt/openssl` (shared, rpath), liboqs 0.16.0 (static, PIC, `OQS_DIST_BUILD=ON`), oqs-provider 0.12.0 → `/opt/openssl/lib/ossl-modules/oqsprovider.so`. Runtime ships only `/opt/openssl`, puts it first on PATH, runs as uid 10001 `pqca`. Versions are build args.
- `images/oqs-base/openssl.cnf`: activates `default` + `oqsprovider`; read only by `/opt/openssl` (distro libssl untouched).
- `images/oqs-base/oqs-selftest.sh` (→ `/usr/local/bin/oqs-selftest`, runs during build): for mldsa44/65/87 keygen → self-signed cert → `openssl verify` → OID bytes in DER → sign/verify; prints serving provider; then keygen/cert/verify for hybrid `p384_mldsa65` forced to oqsprovider.

## Verified
- `docker build -f images/oqs-base/Dockerfile -t pqca/oqs-base:dev .` → exit 0, image 187 MB.
- `docker run --rm pqca/oqs-base:dev oqs-selftest` → `OK: mldsa44/65/87 @ default` (sig 2420 / 3309 / 4627 bytes), `OK: p384_mldsa65 @ oqsprovider`, passed.
- `openssl list -providers` → default 3.5.9 active, oqsprovider 0.12.0 active.
- `openssl genpkey -algorithm mldsa65 -propquery provider=oqsprovider` → unsupported (oqsprovider doesn't register pure ML-DSA on OpenSSL 3.5).

## Decisions
- None by the user. OpenSSL 3.5.9 was chosen as the current LTS; flagged below.

## Left open / next
- Team to confirm: use OpenSSL 3.5 native ML-DSA (current image) vs. pin an older OpenSSL so pure ML-DSA comes from oqsprovider.
- Not pinned by digest / checksum yet (sources cloned by tag).
- No Python in the image yet; service images add it.
- CI workflow to build + run `oqs-selftest`.
