# Ubiquitous Language

The vocabulary used when discussing, documenting, or extending this Shamir's Secret Sharing library. Use these terms consistently in code, comments, XML docs, commit messages, and issues.

## Scheme parameters

| Term                          | Definition                                                                                                                | Aliases to avoid                                               |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| **Secret**                    | The original byte sequence the caller wants to protect; the input to splitting and the output of reconstruction.          | plaintext, message, data, payload                              |
| **Share**                     | One of the `n` outputs of splitting, consisting of an **X-coordinate** and a **Y-value** per secret byte.                 | piece, fragment, part, slice                                   |
| **Threshold (`t`)**           | The minimum number of distinct **Shares** required to reconstruct the **Secret**. Must be ≥ 2.                            | minimum shares, quorum, k                                      |
| **Total shares (`n`)**        | The number of **Shares** produced by a single split. Must satisfy `t ≤ n < Prime`.                                        | share count, number of shares, total                           |
| **(t, n) threshold scheme**   | The overall configuration: produce `n` **Shares**, any `t` of which reconstruct the **Secret**.                           | k-of-n scheme, sharing scheme                                  |
| **Prime (`p`)**               | The prime modulus defining the **Finite Field**. Default `257`. Constrains `n < p` and per-element values to `< p`.       | modulus, prime modulus, p (in prose; `Prime` in code is fine)  |

## Mathematical machinery

| Term                          | Definition                                                                                                                | Aliases to avoid                                               |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| **Finite Field**              | The algebraic structure `GF(Prime)` in which all arithmetic for split/reconstruct happens. Implemented by `FiniteField`.  | field, modular arithmetic system                               |
| **Field element**             | An integer in `[0, Prime)`. Each **Secret** byte is treated as one field element under the default prime.                 | residue, modular value                                         |
| **Polynomial**                | A degree-`t-1` polynomial over the **Finite Field**, built per secret byte during splitting.                              | curve, function                                                |
| **Coefficient**               | One of `t` integers defining a **Polynomial**. The **constant term** is the secret byte; the other `t-1` are random.      | factor, weight                                                 |
| **Constant term**             | The `a₀` coefficient of a **Polynomial**, which equals the secret byte being shared by that polynomial.                   | zeroth coefficient, intercept, P(0)                            |
| **X-coordinate**              | The non-zero field element identifying a **Share**. Splitting uses `1..n`. Stored as `Share.X`.                            | x, index, share id, share number                               |
| **Y-value**                   | A polynomial evaluation result stored in a **Share**; one Y-value per secret byte. Stored as `Share.YValues[i]`.          | y, output, evaluation, ordinate                                |
| **Lagrange interpolation**    | The algorithm used by `ReconstructSecret` to recover each secret byte as `P(0)` from `t` distinct **Shares**.             | polynomial fitting, interpolation                              |
| **Modular inverse**           | The field element `x⁻¹` such that `x · x⁻¹ ≡ 1 (mod Prime)`. Computed via `Power(x, Prime - 2)` (Fermat's little theorem). | reciprocal, inverse element                                    |

## Operations

| Term                          | Definition                                                                                                                | Aliases to avoid                                               |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| **Split**                     | Produce `n` **Shares** from a **Secret** under a chosen **Threshold**. `ShamirSecretSharingService.SplitSecret`.          | divide, fragment, shard, encode                                |
| **Reconstruct**               | Recover the **Secret** from `t` distinct **Shares**. `ShamirSecretSharingService.ReconstructSecret`.                      | recover, decode, combine, merge, restore                       |
| **Serialize**                 | Convert a **Share** to its compact string form via `Share.ToString()`.                                                    | encode, stringify, marshal                                     |
| **Parse**                     | Convert the string form back into a **Share** via `Share.Parse()`. Inverse of **Serialize**.                              | deserialize, decode, unmarshal                                 |

## Security & roles

| Term                          | Definition                                                                                                                | Aliases to avoid                                               |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| **Consumer**                  | An application or library that takes a dependency on this NuGet package and calls its public API.                         | caller, client, user                                           |
| **Share holder**              | A party that holds one or more **Shares** out of band. Compromising `t` share holders compromises the **Secret**.         | participant, custodian, share owner                            |
| **CSPRNG**                    | A cryptographically secure random source. This library uses `System.Security.Cryptography.RandomNumberGenerator`.         | RNG (ambiguous), random generator                              |
| **Verifiable Secret Sharing (VSS)** | An extension of SSS that lets reconstructors detect forged or tampered **Shares**. **Not implemented** by this library. | verified sharing, authenticated sharing                        |
| **Share verification**        | Any mechanism that proves a **Share** is genuine. Out of scope for this library; consumers must layer it themselves.      | share authentication, share integrity                          |
| **Perfect secrecy**           | The information-theoretic property that any `< t` **Shares** reveal nothing about the **Secret**.                         | information-theoretic security, unconditional security         |

## Relationships

- A **Split** operation takes a **Secret**, a **Threshold** `t`, and **Total shares** `n`, and produces exactly `n` **Shares**.
- For each byte of the **Secret**, **Split** constructs one degree-`t-1` **Polynomial** whose **Constant term** is that byte.
- Each **Share** holds one **X-coordinate** and one **Y-value** per secret byte (`Share.YValues.Length == secret.Length`).
- **X-coordinates** must be non-zero and distinct across the **Shares** used in a single **Reconstruct** call.
- **Reconstruct** requires `t` **Shares** with distinct **X-coordinates** and the same `YValues.Length`; it then runs **Lagrange interpolation** at `x = 0` to recover each **Constant term**.
- A **Share** carries no reference to the **Prime** it was created under — the **Consumer** must reconstruct with a `ShamirSecretSharingService` configured for the same **Prime**.
- A **Share** carries no reference to the **Threshold** — the **Consumer** must supply the same `t` to **Reconstruct** as was used to **Split**.

## Example dialogue

> **Dev:** "If I **Split** a 16-byte **Secret** with `n=5, t=3`, do I get one **Polynomial** or sixteen?"

> **Domain expert:** "Sixteen — one **Polynomial** per byte of the **Secret**. Each is degree `t-1`, so degree 2 here. The **Constant term** of polynomial `i` is the `i`-th secret byte; the other two **Coefficients** are random."

> **Dev:** "And the **Shares** themselves?"

> **Domain expert:** "Five **Shares**, each with **X-coordinate** `1` through `5` and sixteen **Y-values** — one **Y-value** per **Polynomial**, evaluated at that share's `X`. To **Reconstruct**, you bring back any three **Shares**, and **Lagrange interpolation** at `x = 0` recovers each **Constant term**, i.e. each secret byte."

> **Dev:** "What stops me from passing **Shares** that came from different splits?"

> **Domain expert:** "Nothing — the library has no **Share verification**. If a **Share holder** swaps a **Share** for a fake one with the same shape, **Reconstruct** silently returns the wrong **Secret**. That's the **VSS** gap documented in `STRIDE.md`."

> **Dev:** "So `Share.Parse` doesn't catch it either?"

> **Domain expert:** "No. **Parse** only restores the **X-coordinate** and **Y-values** as integers — it has no **Prime** context and no integrity tag. Detecting forged shares is the **Consumer**'s job."

## Flagged ambiguities

- **"share count", "number of shares", "total"** are all used informally for **Total shares (`n`)**. Prefer `n` in math contexts and "**Total shares**" in prose. Reserve "share count" for actual `.Count`/`.Length` reads of a collection.
- **"prime" vs "modulus" vs "prime modulus"** all refer to the same value (`FiniteField.Prime`). Use **Prime** in prose; `Prime` in code (the public property already settles this).
- **"secret"** can mean the *input* to **Split** or the *output* of **Reconstruct**. They are byte-for-byte identical on a successful round-trip; if you need to disambiguate, say "original **Secret**" vs "reconstructed **Secret**".
- **`Share.YValues` (code) vs "y-coordinates" / "y values" / "Y values" (prose).** Settle on **Y-value** (hyphenated, singular) in prose, matching **X-coordinate**. The code identifier `YValues` is fine; "y-coordinate" is acceptable when contrasting with **X-coordinate** in geometric framing.
- **`t` vs "threshold" vs "minimum shares".** Use **Threshold** in prose; `t` as the parameter name. Avoid "quorum" — borrowed from consensus systems, where it means something different.
- **"reconstruct" vs "recover" vs "combine".** Use **Reconstruct** for the library operation. "Recover" is fine in security prose ("an attacker can recover the secret"). Avoid "combine" and "merge" — they suggest a symmetric operation, which **Reconstruct** is not (it needs `t` distinct **X-coordinates**, not just any `t` **Shares**).
- **"share holder" vs "participant" vs "custodian".** Use **Share holder**. "Participant" is overloaded in cryptographic protocol literature; "custodian" suggests a legal/financial role this library doesn't model.
- **"consumer" vs "caller" vs "user".** Use **Consumer** for an application or library that depends on this NuGet package. "User" should be avoided — the library has no notion of human users.
- **"random coefficients" vs "polynomial coefficients".** Both are correct, but the **Constant term** is *not* random — it is the secret byte. When precision matters, say "the `t-1` random **Coefficients**".
