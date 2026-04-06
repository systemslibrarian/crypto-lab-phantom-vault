# Phantom Vault

**Live:** [https://systemslibrarian.github.io/crypto-lab-phantom-vault/](https://systemslibrarian.github.io/crypto-lab-phantom-vault/)

## What This Is
Phantom Vault is a stateless password manager that derives service-specific passwords on demand. It does not store passwords, vault files, accounts, sync data, or recovery blobs. Every output is generated locally in the browser from deterministic cryptographic steps.

The design goal is simple: replace storage with reproducible math. The same inputs always produce the same password, so you can regenerate credentials on any device without exporting secrets.

## How It Works
Pipeline:

1. Master passphrase + context (`service:username:version`) is stretched with PBKDF2-SHA-256.
2. The 32-byte PBKDF2 output instantiates an HMAC-DRBG state machine.
3. DRBG bytes are generated deterministically per NIST SP 800-90A Rev.1 §10.1.2.
4. Bytes are mapped to a selected charset using rejection sampling (no modulo bias).
5. Character class coverage is enforced for enabled groups.

## Why It's Safe
- Zero persistence by design: no database, backend, localStorage, sessionStorage, or IndexedDB.
- Deterministic derivation: reproducible outputs from audited input transformations.
- High PBKDF2 cost (600,000 iterations) raises brute-force cost for offline attackers.
- HMAC-DRBG state snapshots are visible for auditability and education.

## Why It's Not Magic
If the master passphrase is compromised, every derived password is compromised. Statelessness removes storage risk, but cannot remove passphrase risk. Use a long, unique passphrase with high entropy.

## Rotation
Increment `version` (1, 2, 3...) to rotate passwords for a service. Old versions still regenerate old passwords, so migrations can be staged safely.

## Tech Stack
| Component | Choice |
| --- | --- |
| Build | Vite + TypeScript (strict) |
| Styling | Tailwind CSS + CSS variables |
| Key Stretching | WebCrypto PBKDF2-SHA-256 |
| DRBG | In-house HMAC-DRBG (SP 800-90A Rev.1 §10.1.2) |
| Deploy | GitHub Pages via GitHub Actions |

## Local Setup
```bash
npm install
npm run dev
npm run type-check
npm run build
```

Build output is written to `out/`.

## Related Projects
- corrupted-oracle: DRBG backdoor demonstration and analysis lineage.
- crypto-compare CSPRNG category: comparative references for deterministic RNG systems.
- quantum-vault-kpqc: post-quantum-oriented vault exploration.

## Data Sources
- NIST SP 800-90A Rev.1, HMAC-DRBG (§10.1.2)
- NIST SP 800-132, PBKDF2 recommendations
- OWASP Password Storage Cheat Sheet

## Limitations
> Stateless derivation eliminates storage attack surface, not passphrase compromise risk.
> Protect the master passphrase or all derived credentials are exposed.

## 1 Corinthians 10:31
So whether you eat or drink or whatever you do, do it all for the glory of God.
