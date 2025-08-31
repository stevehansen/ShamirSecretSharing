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

1. **ShamirSecretSharing** - Main library containing the core implementation
   - `ShamirSecretSharingService.cs`: Main service class for splitting and reconstructing secrets
   - `FiniteField.cs`: Implements arithmetic operations in Galois Field GF(p)
   - `Share.cs`: Defines the Share record with serialization/deserialization logic

2. **ShamirSecretSharingTests** - MSTest unit test project using MSTest.Sdk 3.9.1

3. **ShamirSecretSharing.Console** - Console application for interactive testing

### Key Design Decisions

- Uses GF(257) by default for finite field arithmetic (suitable for byte arrays, as 257 is the smallest prime > 255)
- Implements (t, n) threshold scheme where n = total shares, t = threshold for reconstruction
- Share serialization format: "X:Y0,Y1,Y2,..." for easy storage/transmission
- Uses `System.Security.Cryptography.RandomNumberGenerator` for cryptographic randomness
- All warnings are treated as errors (`TreatWarningsAsErrors=true`)
- Latest C# language features and nullable reference types are enabled

### Security Considerations

- Each byte of the secret becomes a field element (0-255)
- Maximum shares (n) is limited by Prime - 1 (256 for default prime 257)
- Individual shares must be kept secret - exposure of t shares allows reconstruction
- This is a basic SSS implementation without share verification (no VSS)