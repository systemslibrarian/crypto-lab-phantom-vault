# crypto-lab-phantom-vault

## What It Is

Phantom Vault is a stateless password derivation demo that combines PBKDF2-SHA-256, HMAC-DRBG (SP 800-90A Rev.1 §10.1.2), and rejection sampling to deterministically produce service-specific passwords. It solves the problem of storing synced password vault data by regenerating credentials from a master passphrase plus context (`service`, `username`, and `version`). The model is symmetric and deterministic: whoever knows the same inputs can regenerate the same output. This is not asymmetric cryptography, zero-knowledge proof storage, or threshold key management, and it does not provide account recovery if the passphrase is lost.

## When to Use It

- You want deterministic per-service passwords without syncing a vault: the same inputs always reproduce the same password on any device.
- You need explicit rotation by version number: incrementing `version` gives a new output while old versions remain reproducible.
- You want an auditable educational pipeline: the UI exposes progress and DRBG state snapshots so each derivation stage is inspectable.
- You should not use it when users need recovery workflows: because no secrets are stored, forgotten master passphrases cannot be recovered.
- You should not use it where policy requires random one-time generated passwords per account: this design is deterministic by definition.
- Do NOT use it to protect real credentials — it is an educational demo, not a hardened password manager.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-phantom-vault](https://systemslibrarian.github.io/crypto-lab-phantom-vault/)**

The demo derives passwords in-browser from a master passphrase plus service context and selected charset rules. You can tune service, username, version, output length, and character class toggles (`lowercase`, `uppercase`, `digits`, `symbols`), then run derivation and inspect pipeline/proof output. The demo does not encrypt/decrypt stored payloads; it only derives deterministic passwords.

The strength readout reports **effective entropy** as `min(master-passphrase entropy, output-format ceiling)`, not the format ceiling alone. This is the central lesson of deterministic derivation: the output can never hold more entropy than the secret it started from, so a weak passphrase caps the result no matter how long the password or how large the charset.

## What Can Go Wrong

- Master passphrase compromise cascades globally: if an attacker learns the passphrase, every derived credential can be regenerated.
- Weak or low-entropy passphrase selection: deterministic generation cannot compensate for guessable input material.
- Context collisions (`service`, `username`, `version`) across accounts: reused context produces identical outputs and defeats separation.
- Incorrect implementation of rejection sampling: modulo-biased mapping would skew distribution and reduce effective password strength.
- Operational misuse of versioning: failing to track version changes can lock users out after rotation.

## Real-World Usage

- PKCS #5 / RFC 8018 PBKDF2: defines PBKDF2 for password-based key derivation used broadly in application and credential protection workflows.
- NIST SP 800-132: recommends PBKDF2 for deriving cryptographic keys from passwords in federal guidance.
- NIST SP 800-90A Rev.1 HMAC-DRBG: standardizes the DRBG construction implemented by this project for deterministic pseudorandom byte generation.
- OpenSSL PKCS #8 encrypted private keys (`PBES2`): commonly uses PBKDF2 parameters when protecting private keys with passphrases.
- WPA2-PSK (`PBKDF2-HMAC-SHA1`): derives Wi-Fi pre-shared key material from passphrases using the PBKDF2 design family.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-phantom-vault
cd crypto-lab-phantom-vault
npm install
npm run dev
```

## Related Demos

- [crypto-lab-kdf-arena](https://systemslibrarian.github.io/crypto-lab-kdf-arena/) — compares HKDF, PBKDF2, scrypt, and Argon2id.
- [crypto-lab-bcrypt-forge](https://systemslibrarian.github.io/crypto-lab-bcrypt-forge/) — bcrypt password hashing and cost factors.
- [crypto-lab-drbg-arena](https://systemslibrarian.github.io/crypto-lab-drbg-arena/) — HMAC_DRBG, CTR_DRBG, and Hash_DRBG per NIST SP 800-90A.
- [crypto-lab-corrupted-oracle](https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/) — DRBG backdoor demonstration (Dual_EC_DRBG) and analysis lineage.
- [crypto-lab-quantum-vault-kpqc](https://systemslibrarian.github.io/crypto-lab-quantum-vault-kpqc/) — post-quantum-oriented vault exploration.

## Verifying Correctness

A deterministic crypto pipeline is only trustworthy if you can prove each stage is correct. This project ships that proof rather than asserting it in comments:

- **HMAC-DRBG known-answer test.** `src/crypto/hmac-drbg.test.ts` runs the official NIST CAVP HMAC_DRBG / SHA-256 vector (no-reseed, prediction-resistance-false). If the implementation deviates from SP 800-90A Rev.1 §10.1.2 by a single bit, this test fails.
- **Uniform-mapping test.** `npm run verify:uniformity` maps 100,000 random bytes through the rejection sampler and runs a chi-square goodness-of-fit test against the uniform distribution, comparing the statistic to the computed critical value (df = charset − 1, with a strict α = 1e-4 so the automated check is non-flaky while still catching genuine bias). This demonstrates that rejection sampling removes the modulo bias that `byte % N` would introduce.
- **Pipeline property tests.** `src/derive/pipeline.test.ts` asserts the three behavioral claims the UI makes: determinism (same inputs → same password), rotation (a new `version` → a new password, old versions still reproducible), and context separation (changing `service`/`username` changes the output).

Run everything with:

```bash
npm install
npm run check   # type-check (app + tests) + tests + uniformity
npm run build
```

## Data Sources

- NIST SP 800-90A Rev.1, HMAC-DRBG (§10.1.2)
- NIST SP 800-132, PBKDF2 recommendations
- NIST CAVP DRBGVS HMAC_DRBG/SHA-256 known-answer vectors (used in the test suite)
- OWASP Password Storage Cheat Sheet

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
