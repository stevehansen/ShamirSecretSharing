# ShamirSecretSharing - STRIDE Threat Model

**Created:** 2026-02-25
**Version:** v1
**Next review date:** 2029-02-25

## System Overview

### Application Description

A pure C# implementation of Shamir's Secret Sharing (SSS) distributed as a NuGet package targeting .NET 8/9. The library allows splitting byte array or string secrets into `n` shares with a `(t, n)` threshold scheme, where any `t` shares can reconstruct the original secret. It has no external dependencies beyond the .NET BCL.

### Components

| Component | Type | Description |
|-----------|------|-------------|
| `ShamirSecretSharingService` | Public API | Core service for splitting and reconstructing secrets |
| `FiniteField` | Public API | Arithmetic operations in GF(p), default p=257 |
| `Share` | Public API | Record type holding share data with hex serialization |
| `ShamirSecretSharing.Console` | Demo app | Interactive console application (not packaged) |

### Data Flow

```
                    ┌─────────────────────────────────────┐
                    │        Consumer Application         │
                    │                                     │
                    │  secret (byte[]/string)             │
                    │       │                             │
                    │       ▼                             │
  ┌──────────┐     │  ┌──────────────────────────┐       │
  │ .NET RNG │◄────┼──│ ShamirSecretSharingService│       │
  │ (CSPRNG) │     │  │                          │       │
  └──────────┘     │  │  SplitSecret()           │       │
                    │  │    │                     │       │
                    │  │    ├── FiniteField.GF(p) │       │
                    │  │    │                     │       │
                    │  │    ▼                     │       │
                    │  │  Share[] (n shares)      │       │
                    │  │                          │       │
                    │  │  ReconstructSecret()     │       │
                    │  │    │                     │       │
                    │  │    ├── Lagrange interp.  │       │
                    │  │    │                     │       │
                    │  │    ▼                     │       │
                    │  │  byte[] (secret)         │       │
                    │  └──────────────────────────┘       │
                    └─────────────────────────────────────┘
```

### Trust Boundaries

| Boundary | From | To | Description |
|----------|------|----|-------------|
| TB-01 | Consumer application | Library API | Untrusted input: secret data, share data, parameters |
| TB-02 | Library | .NET CSPRNG | Trusted: system cryptographic RNG |
| TB-03 | Library | NuGet consumers | Package distribution via NuGet.org |

### Data Classification

| Data | Classification | Location | Lifetime |
|------|---------------|----------|----------|
| Secret (plaintext) | **Critical** | Managed heap (caller-owned) | Until GC collection |
| Polynomial coefficients | **Critical** | Managed heap (transient) | Until GC collection |
| Share Y-values | **Sensitive** | Managed heap / serialized strings | Caller-controlled |
| Share X-coordinates | Low | Public metadata | Caller-controlled |
| Prime modulus | Low | Configuration | Instance lifetime |

---

## STRIDE Analysis

### S — Spoofing

| ID | Threat | Attack Path | Likelihood | Impact | Score | Mitigation |
|----|--------|-------------|:----------:|:------:|:-----:|------------|
| S-01 | Malicious share injection | Attacker provides fabricated shares during reconstruction, causing recovery of incorrect secret | 2 | 3 | 6 | No built-in mitigation — SSS does not include share verification. Documented as known limitation. Consumers should implement VSS or out-of-band share authentication. |
| S-02 | NuGet package spoofing | Attacker publishes a similarly-named package or compromises the publish pipeline | 1 | 4 | 4 | Package is signed and published from a known repository. Consumers should verify package source and use lock files. |

**Countermeasures in place:**
- S-01: Documented in README and security paper as a known limitation (no VSS)
- S-02: Package published from verified GitHub repository

### T — Tampering

| ID | Threat | Attack Path | Likelihood | Impact | Score | Mitigation |
|----|--------|-------------|:----------:|:------:|:-----:|------------|
| T-01 | Share data tampered in storage/transit | Attacker modifies serialized share strings, causing reconstruction to produce incorrect secret without error | 2 | 3 | 6 | No integrity protection on shares. Library silently reconstructs a wrong secret from tampered shares. Consumers must implement their own integrity checks (HMAC, signatures). |
| T-02 | Dependency supply chain compromise | Compromised NuGet dependency introduces malicious code | 1 | 4 | 4 | Library has zero external dependencies. Only risk is the .NET SDK itself. Renovate monitors dependency updates for the test project. |

**Countermeasures in place:**
- T-01: None — inherent limitation of basic SSS
- T-02: Zero runtime dependencies; `TreatWarningsAsErrors` and code style enforcement in build

### R — Repudiation

| ID | Threat | Attack Path | Likelihood | Impact | Score | Mitigation |
|----|--------|-------------|:----------:|:------:|:-----:|------------|
| R-01 | No audit trail for share operations | No logging of split/reconstruct operations; cannot prove which shares were generated or used | 2 | 2 | 4 | Library is intentionally stateless and log-free. Consumers should implement their own audit logging around library calls. |

**Countermeasures in place:**
- R-01: By design — a cryptographic library should not log secret material. Auditing is the consumer's responsibility.

### I — Information Disclosure

| ID | Threat | Attack Path | Likelihood | Impact | Score | Mitigation |
|----|--------|-------------|:----------:|:------:|:-----:|------------|
| I-01 | Secret and coefficients persist in managed memory | Secret bytes, polynomial coefficients, and intermediate values reside in .NET managed heap memory and cannot be reliably zeroed. Memory dumps, crash dumps, or GC relocation may expose sensitive data. | 2 | 4 | **8** | No mitigation in current implementation. .NET managed memory does not support deterministic zeroing of `byte[]`/`int[]`. Consumers operating in high-security environments should consider process isolation or hardware security modules. |
| I-02 | Coefficient bias from modulo reduction | Random coefficients are generated as `byte % Prime`. For Prime=257, coefficient value 256 is never generated (byte range is 0-255), creating a non-uniform distribution over GF(257). | 2 | 2 | 4 | Bias is minimal for default prime (1/257 probability gap). For smaller custom primes, bias increases. Could be fixed with rejection sampling. |
| I-03 | Timing side channels in finite field arithmetic | `FiniteField` operations (especially `Power`/`Inverse` via modular exponentiation) are not constant-time. An attacker with precise timing measurements could infer coefficient or secret values. | 1 | 3 | 3 | Low practical risk for a library typically used in application-level code. Constant-time implementations would be needed for use in constrained or adversarial-observable environments. |
| I-04 | Share accumulation leading to secret recovery | An attacker who compromises `t` or more share holders over time can reconstruct the secret. This is inherent to the SSS scheme. | 2 | 4 | **8** | Inherent property of threshold secret sharing — not a bug. Consumers should enforce share isolation, access controls, and periodic secret rotation. |

**Countermeasures in place:**
- I-01: None — .NET platform limitation
- I-02: Bias acknowledged; minimal impact at default prime
- I-03: Standard implementation; not designed for side-channel-resistant environments
- I-04: Documented in README and security paper

### D — Denial of Service

| ID | Threat | Attack Path | Likelihood | Impact | Score | Mitigation |
|----|--------|-------------|:----------:|:------:|:-----:|------------|
| D-01 | Resource exhaustion from large inputs | Caller passes extremely large secret byte arrays, causing proportional memory allocation for shares (n arrays of secret length) and O(secret.Length × n × t) CPU usage | 2 | 2 | 4 | Input validation rejects null/empty secrets and enforces n < Prime. No upper bound on secret length. Consumers should enforce their own size limits. |
| D-02 | Malformed share strings cause parse errors | Invalid serialized share strings passed to `Share.Parse()` cause `FormatException` or `ArgumentException` | 2 | 1 | 2 | Parse method validates format and throws descriptive exceptions. Consumer should handle parse exceptions. |

**Countermeasures in place:**
- D-01: Parameter validation for n, t, and prime bounds
- D-02: Robust parsing with specific exception types

### E — Elevation of Privilege

| ID | Threat | Attack Path | Likelihood | Impact | Score | Mitigation |
|----|--------|-------------|:----------:|:------:|:-----:|------------|
| E-01 | FiniteField misuse with non-prime modulus | `FiniteField` is public and accepts any integer > 1. Using a non-prime modulus breaks the mathematical guarantees of the finite field, leading to incorrect or insecure share generation (non-invertible elements). | 2 | 3 | 6 | No primality validation. Constructor comment notes this limitation. Consumers using custom primes must ensure they are actually prime. |
| E-02 | Share.Parse does not validate field bounds | Parsed Y-values are not checked against any prime/field bounds. Shares with Y-values outside the valid field range could cause incorrect reconstruction. | 2 | 2 | 4 | Share is a data container and does not know the field context. Validation occurs implicitly during reconstruction via modular arithmetic. |

**Countermeasures in place:**
- E-01: Documented; default prime 257 is correct
- E-02: Modular arithmetic in reconstruction provides implicit bounds

---

## Risk Summary

### High Priority Threats (Score >= 8)

| ID | Threat | Score | Status |
|----|--------|:-----:|--------|
| I-01 | Secret and coefficients persist in managed memory | 8 | Accepted — .NET platform limitation; recommend consumer-level process isolation |
| I-04 | Share accumulation leading to secret recovery | 8 | Accepted — inherent to SSS scheme; documented in README and security paper |

### Residual Risks

- **No Verifiable Secret Sharing (VSS):** The library cannot detect malicious or tampered shares. This is the most significant functional gap for adversarial environments (S-01, T-01).
- **Coefficient distribution bias:** The modulo reduction in coefficient generation creates a small but measurable bias (I-02). Low practical impact but deviates from ideal uniform randomness.
- **FiniteField lacks primality check:** Consumers using custom primes could silently break security guarantees (E-01).

---

## Security Controls Summary

| Category | Implementation |
|----------|---------------|
| Randomness | `System.Security.Cryptography.RandomNumberGenerator` (CSPRNG) |
| Input validation | Parameter bounds checking on n, t, prime, secret content |
| Dependencies | Zero runtime dependencies; Renovate for dev dependency updates |
| Build hardening | `TreatWarningsAsErrors`, `EnforceCodeStyleInBuild`, nullable reference types |
| Documentation | Security paper in `docs/security-paper.md`; limitations documented in README |
| Testing | MSTest suite covering core operations, edge cases, and error paths |

---

## Review History

| Version | Date | Reviewer | Changes |
|---------|------|----------|---------|
| v1 | 2026-02-25 | Claude Code | Initial STRIDE threat model |

---

## References

- [STRIDE Threat Model (Microsoft)](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- A. Shamir, "How to share a secret," Communications of the ACM, vol. 22, no. 11, 1979
- Project security paper: [`docs/security-paper.md`](docs/security-paper.md)
