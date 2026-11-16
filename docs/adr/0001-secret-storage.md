# ADR-0001: Secret storage for in-cluster services

**Status:** Proposed
**Date:** 2026-11-16
**Deciders:** team (owner: Andrew Rami, containers / Kubernetes / CI/CD)

## Context

Hard rule 5 says secrets never go in files in the repo; they come from Kubernetes Secrets or env vars. Nothing supplies them yet: `deploy/k8s/` holds only `.gitkeep` files.

Secrets we already know we need:

| Secret | Read by |
|---|---|
| `POSTGRES_PASSWORD` + 10 `*_DB_PASSWORD` (`database/init/007_logins.sh`) | postgres (first start only) |
| one DB password per service (`PQCA_DB_PASSWORD_FILE`) | each service, its own only |
| SoftHSM2 user PIN for the intermediate CA token | ca-engine, crl-generator, ocsp-responder (signing) |
| JWT signing key, MFA secrets | api-gateway |
| DUNS / D&B API key (once access exists) | ov-agent |
| Redis password | api-gateway |

Out of scope: CA private keys. The root key stays offline (hard rule 6) and the intermediate key stays inside SoftHSM2. This ADR covers the secrets that unlock those things, not the keys themselves.

Constraints:
- A CA: whoever can read a secret is part of the trust boundary. We want few readers and an audit trail.
- Kubernetes + Kustomize, deployed from GitHub Actions. Self-hosted cluster (DMZ / ZeroTier); no cloud provider has been picked.
- Seven students, one semester. Running the secret store must not become a project of its own.
- No outbound egress for most pods (hard rule 4), so a cloud secret manager means new egress rules.

Whatever we pick, these apply:
- Enable etcd encryption at rest (`EncryptionConfiguration`, `secretbox` or `aescbc`). Without it, a Kubernetes Secret is only base64 in etcd.
- RBAC: no human or CI role gets `get`/`list` on Secrets in the `pqca` namespace except cluster admins.
- Mount secrets as files (`PQCA_DB_PASSWORD_FILE`), not env vars. Env vars leak through `kubectl describe`, `/proc/<pid>/environ` and crash dumps.
- One Secret (or one key) per service, so each pod mounts only its own.

## Options considered

### A. Plain Kubernetes Secrets from a gitignored file (Kustomize `secretGenerator`)
Each overlay has a local `secret.env` (already gitignored via `deploy/k8s/overlays/*/secret*.env`); `kustomize build` turns it into Secrets. Or a person creates them with `kubectl create secret`.

| Dimension | Assessment |
|---|---|
| Complexity | Low |
| Cost | None |
| Scalability | Poor past one or two people; values live on laptops |
| Team familiarity | High |

**Pros:** nothing to install; works today; fine for dev.
**Cons:** no record of who has the values or when they changed; sharing them means sending them by chat; CI needs the plaintext to deploy; rotation is manual.

### B. Sealed Secrets (Bitnami controller)
`kubeseal` encrypts a Secret with the controller's public key; the encrypted `SealedSecret` is committed; only the in-cluster controller can decrypt it.

| Dimension | Assessment |
|---|---|
| Complexity | Low–Med (one controller, one CLI) |
| Cost | None (Apache-2.0) |
| Scalability | Good for a fixed set of secrets |
| Team familiarity | Low, but learned in an hour |

**Pros:** secrets live in git, encrypted, and reviewed like any manifest; CI only applies ciphertext and never sees plaintext; the private key never leaves the cluster.
**Cons:** the controller's private key must be backed up, or a rebuilt cluster can't decrypt anything; sealed values are tied to one cluster and namespace; no dynamic or short-lived credentials; rotation is still manual (re-seal and commit).

### C. SOPS + age (encrypted files in git, decrypted at deploy time)
Secret files are encrypted per value with `age` keys; KSOPS (a Kustomize plugin) or the deploy step decrypts them.

| Dimension | Assessment |
|---|---|
| Complexity | Medium (Kustomize plugin or a decrypt step in CI) |
| Cost | None |
| Scalability | Good; works across clusters |
| Team familiarity | Low |

**Pros:** readable diffs (keys in clear, values encrypted); not tied to one cluster; developers can decrypt locally if they hold a key.
**Cons:** whatever runs `kustomize build` needs an age private key, so CI holds a key that decrypts every secret, which is a bigger blast radius than B; managing key holders is on us.

### D. OpenBao / HashiCorp Vault + External Secrets Operator
A secret store runs in the cluster (or on a separate host). External Secrets Operator (ESO) copies values into Kubernetes Secrets. OpenBao is the open-source (MPL-2.0) fork of Vault; Vault itself has been under the BSL licence since 2023.

| Dimension | Assessment |
|---|---|
| Complexity | High (HA storage, unseal, policies, backups) |
| Cost | None in licences; real time cost to run |
| Scalability | Excellent |
| Team familiarity | Low |

**Pros:** central audit log of every read; per-service policies; versioning and rotation; can grow into option E.
**Cons:** another stateful, security-critical system to run, unseal and back up; if it's down, pods can't start after a restart; its own unseal keys need the same care as the CA's.

### E. OpenBao / Vault database secrets engine (dynamic DB credentials)
Vault creates a short-lived Postgres login per pod (`CREATE ROLE ... VALID UNTIL ... IN ROLE pqca_gateway`) and drops it when the lease ends. Delivered by the Vault Agent sidecar or the Secrets Store CSI driver, so no static Secret object exists.

| Dimension | Assessment |
|---|---|
| Complexity | High (everything in D plus lease handling in services) |
| Cost | None in licences |
| Scalability | Excellent |
| Team familiarity | Low |

**Pros:** no long-lived DB passwords at all; a leaked credential expires within hours; fits our group-role design (`pqca_*` NOLOGIN groups) well, since Vault only adds members.
**Cons:** replaces `007_logins.sh`; Vault needs `CREATEROLE` on Postgres; the pool must reconnect when credentials rotate; `audit_logs.actor_label` (= `session_user`) would show generated names like `v-gateway-x8f2…` instead of `gateway_svc`.

### F. Cloud secret manager (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) via ESO or the CSI driver

| Dimension | Assessment |
|---|---|
| Complexity | Medium |
| Cost | Small per-secret / per-call fees |
| Scalability | Excellent |
| Team familiarity | Low |

**Pros:** managed, audited, HSM-backed KMS; no store to run.
**Cons:** we have no cloud provider and the cluster is self-hosted; needs outbound egress from the cluster (against the spirit of hard rule 4) and cloud credentials, which are one more secret to store.

## Trade-off analysis

The real question is **who can read the plaintext**:
- A: anyone holding the file, plus CI.
- C: anyone holding an age key, plus CI.
- B: only the cluster.
- D/E: only pods whose policy allows it, and every read is logged.

For a CA, keeping plaintext out of CI and out of chat matters more than convenience. That rules out A for anything but dev, and makes C weaker than B.

D and E are the strongest, but they add a second security-critical system with its own unseal ceremony. That's a lot for one semester while the CA itself (SoftHSM2, signing, CRL/OCSP) is unfinished. E also changes how audit entries name the actor.

## Recommendation (to confirm)

1. **Dev overlay:** option A (`secretGenerator` + gitignored `secret.env`, with a committed `secret.env.example`). Throwaway values; zero setup.
2. **Prod overlay:** option B (Sealed Secrets), plus etcd encryption at rest, Secret-read RBAC limited to cluster admins, and file mounts. Back up the controller's sealing key offline, alongside the root CA material procedures.
3. **Later, if time allows:** move DB credentials to option E (OpenBao dynamic credentials). It's a strong demo of least privilege but should come after M2.

## Consequences
- Easier: reviewing secret changes in PRs (B); CI never handles plaintext.
- Harder: rebuilding the prod cluster requires restoring the sealing key; adding a secret means running `kubeseal`.
- Revisit: when the cluster host or provider is chosen; if we adopt OpenBao (E), `007_logins.sh` and the `actor_label` semantics change.

## Action items
1. [ ] Team decides; record the outcome in `claude-context/DECISIONS.md` and set this ADR's status.
2. [ ] Dev overlay: `secretGenerator` + `secret.env.example`; postgres base mounts all DB passwords, each service only its own.
3. [ ] Turn on etcd encryption at rest on the cluster; verify with `etcdctl get /registry/secrets/pqca/<name>` showing `k8s:enc:` instead of plaintext.
4. [ ] If B: install the Sealed Secrets controller, document the `kubeseal` workflow and the sealing-key backup in a runbook.
5. [ ] Decide where the SoftHSM2 PIN lives. It unlocks the intermediate CA key, so it may deserve stricter handling than the DB passwords.
