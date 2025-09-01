# Shamir's Secret Sharing in C#

![icon](icon.png)

[![NuGet](https://img.shields.io/nuget/v/ShamirSecretSharing.svg)](https://www.nuget.org/packages/ShamirSecretSharing/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE.txt)
![Tests](https://img.shields.io/badge/tests-MSTest-orange)

A pure C# implementation of Shamir's Secret Sharing (SSS) scheme, designed for .NET 8/9 without external library dependencies beyond the .NET Base Class Library.

## Overview

Shamir's Secret Sharing allows you to split a secret (e.g., a password, an encryption key, or any piece of data) into multiple unique parts called "shares." The original secret can only be reconstructed if a sufficient number of these shares (a predefined threshold) are brought together. If fewer than the threshold number of shares are available, the secret remains completely hidden.

This is a `(t, n)` threshold scheme:
-   `n`: The total number of shares generated.
-   `t`: The minimum number of shares required to reconstruct the original secret.

## Features

-   **Pure C#:** Written entirely in C#, compatible with modern .NET versions (.NET 8/9).
-   **No External Dependencies:** Relies only on standard .NET libraries (e.g., `System.Security.Cryptography` for random number generation).
-   **Byte-Oriented:** Primarily designed to split `byte[]` secrets. Convenience methods for `string` secrets (using UTF-8 encoding by default) are also provided.
-   **Finite Field Arithmetic:** Performs calculations in GF(257) by default, suitable for byte-wise secret sharing (each byte 0-255 becomes a field element). The prime can be configured.
-   **Share Serialization:** Includes methods to serialize shares to and from strings for easier storage or transmission.
-   **Authenticated Shares:** Support for cryptographically authenticated shares with HMAC-SHA256 signatures to detect tampering and temporal validity tracking.
-   **Unit Tested:** Comes with a set of MSTest unit tests to verify correctness.

## How to Use

### Core Classes

1.  **`ShamirSecretSharingService`**: The main service class for splitting and reconstructing secrets.
    ```csharp
    using ShamirSecretSharing;

    var sss = new ShamirSecretSharingService(); // Uses default prime 257
    // var sssCustomPrime = new ShamirSecretSharingService(prime: 503); // Optional custom prime
    ```

2.  **`Share`**: A record representing a single share.
    ```csharp
    // public record Share(int X, int[] YValues);
    // X: The unique (non-zero) x-coordinate of this share.
    // YValues: An array of y-coordinates, one for each byte of the original secret.
    ```

### Splitting a Secret

To split a secret string into 5 shares, with any 3 required for reconstruction:

```csharp
using ShamirSecretSharing;
using System.Text;
using System.Collections.Generic;

var sss = new ShamirSecretSharingService();
string originalSecret = "My Top Secret Data!";
int n = 5; // Total shares
int t = 3; // Threshold

// Split a string (UTF-8 encoding by default)
Share[] shares = sss.SplitSecret(originalSecret, n, t);

// Or split a byte array
// byte[] secretBytes = Encoding.UTF8.GetBytes(originalSecret);
// Share[] shares = sss.SplitSecret(secretBytes, n, t);

foreach (var share in shares)
{
    Console.WriteLine($"Share {share.X} (raw): {share.ToString()}");
    Console.WriteLine($"Share {share.X} (serialized): {share.SerializeToString()}");
    // Store/distribute these serializedShare strings securely.
}
```

### Reconstructing a Secret

To reconstruct the secret using a sufficient number of (serialized) shares:

```csharp
// Assume you have collected at least 't' serialized shares
List<string> collectedSerializedShares = new List<string>
{
    // Example: shares[0].SerializeToString(), shares[2].SerializeToString(), shares[4].SerializeToString()
    "1:167,129,32,84,111,114,32,83,101,99,114,101,116,32,68,97,116,97,33", // Placeholder
    "3:187,157,188,112,111,114,32,83,101,99,114,101,116,32,68,97,116,97,33", // Placeholder
    "5:207,185,20,140,111,114,32,83,101,99,114,101,116,32,68,97,116,97,33"  // Placeholder
};

List<Share> sharesForReconstruction = new List<Share>();
foreach (string sShareStr in collectedSerializedShares)
{
    sharesForReconstruction.Add(Share.DeserializeFromString(sShareStr));
}

if (sharesForReconstruction.Count >= t)
{
    try
    {
        string reconstructedSecret = sss.ReconstructSecretString(sharesForReconstruction, t);
        Console.WriteLine($"Reconstructed Secret: {reconstructedSecret}");

        // Or for byte arrays:
        // byte[] reconstructedBytes = sss.ReconstructSecret(sharesForReconstruction, t);
        // Console.WriteLine($"Reconstructed Secret (bytes): {Encoding.UTF8.GetString(reconstructedBytes)}");
    }
    catch (ArgumentException ex)
    {
        Console.WriteLine($"Reconstruction failed: {ex.Message}"); // e.g., not enough distinct shares
    }
}
else
{
    Console.WriteLine("Not enough shares to reconstruct the secret.");
}
```

### Share Serialization

The `Share` record provides methods for serialization:
-   `share.ToString()`: Converts a `Share` object to a string like `"X:Y0,Y1,Y2,..."`.
-   `Share.Parse(string s)`: Converts a serialized string back into a `Share` object.

### Authenticated Shares

For enhanced security, the library provides authenticated shares that include cryptographic signatures to detect tampering:

```csharp
using ShamirSecretSharing;

// Create an authenticator with a shared key
var key = Encoding.UTF8.GetBytes("YourSecureKeyAtLeast16BytesLong!");
var authenticator = new HmacShareAuthenticator(key);

// Or create with a random key
var (authenticator, generatedKey) = HmacShareAuthenticator.CreateWithRandomKey();

// Create the authenticated service
var authService = new AuthenticatedShamirService(authenticator);

// Split a secret with authentication
string secret = "Sensitive data requiring tamper protection";
int n = 5; // Total shares
int t = 3; // Threshold
var expiresIn = TimeSpan.FromDays(7); // Optional expiration

AuthenticatedShare[] authShares = authService.SplitAuthenticatedSecret(
    secret, n, t, expiresIn);

// Serialize authenticated shares for storage/transmission
foreach (var authShare in authShares)
{
    string serialized = authShare.ToString();
    Console.WriteLine($"Authenticated Share {authShare.Share.X}: {serialized}");
}

// Reconstruct from authenticated shares
var collectedShares = authShares.Take(t).ToList(); // Use any t shares
string reconstructed = authService.ReconstructAuthenticatedSecretString(
    collectedShares, t);

// The service automatically validates signatures and expiration
// If any share is tampered with or expired, reconstruction will fail with an exception
```

#### Key Features of Authenticated Shares:

-   **Tamper Detection:** Each share includes an HMAC-SHA256 signature that is verified during reconstruction
-   **Temporal Validity:** Shares can have optional expiration times
-   **Validation:** The `ValidateShares` method allows checking share integrity before reconstruction
-   **Flexible Authentication:** The `IShareAuthenticator` interface allows custom authentication implementations

### Prime Number (`_field.Prime`)

-   The default prime used is 257. This is suitable for splitting `byte[]` secrets, as each byte (0-255) can be a field element.
-   The prime must be greater than the maximum value of an individual element of your secret and also greater than `n` (the total number of shares).
-   You can specify a custom prime in the `ShamirSecretSharingService` constructor if needed, but ensure your secret data and `n` are compatible.

## Security Considerations

-   **Randomness:** The security of SSS relies on the cryptographic randomness of the coefficients chosen for the polynomial. This implementation uses `System.Security.Cryptography.RandomNumberGenerator` for this purpose.
-   **Share Security:** Each individual share must be kept secret. If an attacker obtains `t` or more shares, they can reconstruct the secret. SSS protects against the loss/compromise of *up to* `t-1` shares.
-   **Integrity/Authenticity:** The library now provides authenticated shares using HMAC-SHA256 signatures to protect against malicious or corrupted shares. The `AuthenticatedShamirService` automatically validates share integrity during reconstruction, rejecting tampered shares.
-   **Key Management:** When using authenticated shares, the HMAC key must be securely shared among all authorized parties. Consider using asymmetric authentication (RSA/ECDSA) for scenarios where key distribution is challenging.
-   **Side Channels:** As with any cryptographic implementation, consider potential side-channel attacks depending on the environment where share generation or reconstruction occurs.

## Limitations

-   The current implementation is primarily optimized for `byte[]` secrets using GF(257). Adapting it for secrets composed of larger data types (e.g., `int` arrays) would require adjusting the prime and potentially the `YValues` storage in the `Share` record.
-   The maximum number of shares (`n`) is limited by `Prime - 1`. For the default prime 257, `n` can be at most 256.

## Project Structure

-   `FiniteField.cs`: Implements arithmetic operations in a Galois Field GF(p).
-   `Share.cs`: Defines the `Share` record and its serialization/deserialization logic.
-   `ShamirSecretSharingService.cs`: Contains the core logic for splitting and reconstructing secrets.
-   `AuthenticatedShare.cs`: Extends shares with cryptographic signatures and timestamps.
-   `IShareAuthenticator.cs`: Interface for implementing different authentication strategies.
-   `HmacShareAuthenticator.cs`: HMAC-SHA256 based share authentication implementation.
-   `AuthenticatedShamirService.cs`: Service for creating and verifying authenticated shares.
-   `ShamirSecretSharingTests/` (Separate Project): Contains MSTest unit tests.
-   `ShamirSecretSharing.Console/` (Separate Project): Contains a console application for testing the library interactively.

## Building and Testing

1.  Open the solution in Visual Studio or use the .NET CLI.
2.  Build the solution: `dotnet build`
3.  Run tests (from the solution directory or test project directory): `dotnet test`