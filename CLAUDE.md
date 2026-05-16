# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build
```bash
# Build the solution (Debug)
dotnet build

# Release build
dotnet build -c Release

# Clean
dotnet clean
```

### Test
```bash
# Run all tests
dotnet test

# Verbose output
dotnet test --logger "console;verbosity=detailed"

# Run a single test by name
dotnet test --filter "FullyQualifiedName~TestMethodName"
```

### Package & Run
```bash
# Create NuGet package (+ snupkg symbol package)
dotnet pack -c Release

# Run the interactive console demo
dotnet run --project ShamirSecretSharing.Console
```

## Architecture

Pure-C# Shamir's Secret Sharing library targeting .NET 8/9, with no dependencies beyond the BCL. Three projects in the solution:

1. **ShamirSecretSharing** — main library (multi-targets `net8.0;net9.0`)
   - `ShamirSecretSharingService.cs`: splits/reconstructs secrets. `SplitSecret` runs one polynomial *per byte* of the secret, evaluating it at `x = 1..n`; `ReconstructSecret` recovers each byte via Lagrange interpolation at `x = 0`.
   - `FiniteField.cs`: arithmetic in GF(p). Modular inverse uses Fermat's little theorem (`Power(n, p-2)`), which requires p to be prime — the constructor does **not** verify primality.
   - `Share.cs`: `record` with `X` (non-zero x-coordinate) and `YValues[]` (one entry per secret byte). Serializes via `ToString()` / `Parse()`.

2. **ShamirSecretSharingTests** — MSTest (MSTest.Sdk 3.9.1), `net8.0` only, method-level parallel execution (`MSTestSettings.cs`).

3. **ShamirSecretSharing.Console** — interactive demo of split/reconstruct.

### Key design decisions

- Default prime is **GF(257)** (smallest prime > 255), so each secret byte fits in one field element. With this prime, `n` (total shares) is capped at 256.
- `(t, n)` threshold scheme — `t` shares are required and sufficient to reconstruct. `t` must be ≥ 2.
- Coefficients are sampled with `RandomNumberGenerator.GetInt32(Prime)` (`System.Security.Cryptography`), which is unbiased across `0..Prime-1` for any prime.
- Share string format from `Share.ToString()`: `"X:Y0Y1Y2..."` where `X` and each `Y` are uppercase hex. Y-values with hex length ≤ 2 are emitted as exactly 2 zero-padded hex digits with no separator; longer values are wrapped in commas (e.g. `,1F4,`). `Share.Parse()` is the inverse. This compact encoding assumes `Prime` is small enough that most Y-values fit in two hex digits; it still works for larger primes, just less compactly.

### Build & style enforcement

`Directory.Build.props` applies to every project:
- `TreatWarningsAsErrors=true`
- `EnforceCodeStyleInBuild=true`
- `Nullable=enable`, `ImplicitUsings=enable`, `LangVersion=latest`, `AnalysisLevel=latest`

The library project additionally sets `GenerateDocumentationFile=true`. **Gotcha:** combined with `TreatWarningsAsErrors`, this means any public member without an XML doc comment fails the build (CS1591). When adding public API to `ShamirSecretSharing/`, write the `///` summary at the same time.

### Security model

- Each secret byte is treated as an independent field element; reconstruction is byte-wise.
- Individual shares must stay secret — possession of `t` shares is sufficient to recover the entire secret.
- This is a *basic* SSS implementation: no Verifiable Secret Sharing (VSS), no MAC, no integrity check. A malicious participant supplying a forged share will cause silent reconstruction of the wrong secret.
- A STRIDE-style threat model lives in `STRIDE.md`; a longer write-up is in `docs/security-paper.md`. Consult these before extending the security-relevant code paths.

### Other repo conventions

- Renovate (`renovate.json`) handles dependency updates.
- NuGet metadata (version, authors, license, README, icon) is set in `ShamirSecretSharing/ShamirSecretSharing.csproj`; `EmbedUntrackedSources` and `IncludeSymbols` are on, so `dotnet pack` produces source-linked `.snupkg` symbols.
