# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build Commands
```bash
# Build the solution
dotnet build

# Build in Release mode
dotnet build -c Release

# Clean build artifacts
dotnet clean
```

### Test Commands
```bash
# Run all tests
dotnet test

# Run tests with verbose output
dotnet test --logger "console;verbosity=detailed"

# Run a specific test
dotnet test --filter "FullyQualifiedName~TestMethodName"
```

### Package Commands
```bash
# Create NuGet package
dotnet pack -c Release

# Run the console application for interactive testing
dotnet run --project ShamirSecretSharing.Console
```

## Architecture Overview

This is a Shamir's Secret Sharing cryptographic library implemented in pure C# for .NET 8/9. The solution consists of three projects:

1. **ShamirSecretSharing** - Main library (multi-targets `net8.0;net9.0`)
   - `ShamirSecretSharingService.cs`: Main service class for splitting and reconstructing secrets using Lagrange interpolation
   - `FiniteField.cs`: Implements arithmetic operations in Galois Field GF(p) using Fermat's little theorem for modular inverse
   - `Share.cs`: Record type with hex-based serialization/deserialization via `ToString()`/`Parse()`

2. **ShamirSecretSharingTests** - MSTest unit test project using MSTest.Sdk 3.9.1 (targets `net8.0` only, parallel execution at method level)

3. **ShamirSecretSharing.Console** - Console application for interactive testing

### Key Design Decisions

- Uses GF(257) by default for finite field arithmetic (257 is the smallest prime > 255, suitable for byte arrays)
- Implements (t, n) threshold scheme where n = total shares, t = threshold for reconstruction
- Share serialization uses compact hex format: `"X:Y0Y1Y2..."` where X and Y values are hex-encoded. Y values use fixed 2-hex-digit encoding (zero-padded) for values 0x00-0xFF, and comma-delimited for values >= 0x100 (e.g., `,1F4,`)
- Uses `System.Security.Cryptography.RandomNumberGenerator` for cryptographic randomness
- `Directory.Build.props` enforces `TreatWarningsAsErrors`, `EnforceCodeStyleInBuild`, nullable reference types, and latest C# language version across all projects
- `GenerateDocumentationFile` is enabled on the library project, so all public members require XML doc comments
- Renovate is configured for automated dependency updates

### Security Considerations

- Each byte of the secret becomes a field element (0-255)
- Maximum shares (n) is limited by Prime - 1 (256 for default prime 257)
- Individual shares must be kept secret - exposure of t shares allows reconstruction
- This is a basic SSS implementation without share verification (no VSS)
