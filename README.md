# Phantom Vault

**Live:** [https://systemslibrarian.github.io/crypto-lab-phantom-vault/](https://systemslibrarian.github.io/crypto-lab-phantom-vault/)

## 1. What It Is
Phantom Vault is a stateless password derivation demo that combines PBKDF2-SHA-256, HMAC-DRBG (SP 800-90A Rev.1 §10.1.2), and rejection sampling to deterministically produce service-specific passwords. It solves the problem of storing synced password vault data by regenerating credentials from a master passphrase plus context (`service`, `username`, and `version`). The model is symmetric and deterministic: whoever knows the same inputs can regenerate the same output. This is not asymmetric cryptography, zero-knowledge proof storage, or threshold key management, and it does not provide account recovery if the passphrase is lost.

## 2. When to Use It
- You want deterministic per-service passwords without syncing a vault: the same inputs always reproduce the same password on any device.
- You need explicit rotation by version number: incrementing `version` gives a new output while old versions remain reproducible.
- You want an auditable educational pipeline: the UI exposes progress and DRBG state snapshots so each derivation stage is inspectable.
- You should not use it when users need recovery workflows: because no secrets are stored, forgotten master passphrases cannot be recovered.
- You should not use it where policy requires random one-time generated passwords per account: this design is deterministic by definition.

## 3. Live Demo
Live demo: [https://systemslibrarian.github.io/crypto-lab-phantom-vault/](https://systemslibrarian.github.io/crypto-lab-phantom-vault/)

The demo derives passwords in-browser from a master passphrase plus service context and selected charset rules. You can tune service, username, version, output length, and character class toggles (`lowercase`, `uppercase`, `digits`, `symbols`), then run derivation and inspect pipeline/proof output. The demo does not encrypt/decrypt stored payloads; it only derives deterministic passwords.

## 4. What Can Go Wrong
- Master passphrase compromise cascades globally: if an attacker learns the passphrase, every derived credential can be regenerated.
- Weak or low-entropy passphrase selection: deterministic generation cannot compensate for guessable input material.
- Context collisions (`service`, `username`, `version`) across accounts: reused context produces identical outputs and defeats separation.
- Incorrect implementation of rejection sampling: modulo-biased mapping would skew distribution and reduce effective password strength.
- Operational misuse of versioning: failing to track version changes can lock users out after rotation.

## 5. Real-World Usage
- PKCS #5 / RFC 8018 PBKDF2: defines PBKDF2 for password-based key derivation used broadly in application and credential protection workflows.
- NIST SP 800-132: recommends PBKDF2 for deriving cryptographic keys from passwords in federal guidance.
- NIST SP 800-90A Rev.1 HMAC-DRBG: standardizes the DRBG construction implemented by this project for deterministic pseudorandom byte generation.
- OpenSSL PKCS #8 encrypted private keys (`PBES2`): commonly uses PBKDF2 parameters when protecting private keys with passphrases.
- WPA2-PSK (`PBKDF2-HMAC-SHA1`): derives Wi-Fi pre-shared key material from passphrases using the PBKDF2 design family.

## Related Projects
- corrupted-oracle: DRBG backdoor demonstration and analysis lineage.
- crypto-compare CSPRNG category: comparative references for deterministic RNG systems.
- quantum-vault-kpqc: post-quantum-oriented vault exploration.

## Data Sources
- NIST SP 800-90A Rev.1, HMAC-DRBG (§10.1.2)
- NIST SP 800-132, PBKDF2 recommendations
- OWASP Password Storage Cheat Sheet

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
