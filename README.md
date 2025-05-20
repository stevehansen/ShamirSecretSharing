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
-   **Share Serialization:** Includes methods to serialize shares to and from strings using a colon-delimited hexadecimal format (e.g., `X_hex:Y0_hex:Y1_hex:...`).
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
string originalSecret = "My Top Secret Data!"; // Example secret
int n = 5; // Total shares
int t = 3; // Threshold

// Split a string (UTF-8 encoding by default)
Share[] shares = sss.SplitSecret(originalSecret, n, t);

// Or split a byte array
// byte[] secretBytes = Encoding.UTF8.GetBytes(originalSecret);
// Share[] shares = sss.SplitSecret(secretBytes, n, t);

foreach (var share in shares)
{
    string serializedShare = share.ToString();
    Console.WriteLine($"Share {share.X} (serialized): {serializedShare}");
    // Example output for a share like (X=1, YValues=[100, 200]): Share 1 (serialized): 1:64:C8
    // (Actual Y values depend on the secret and random polynomial)
    // Store/distribute these serializedShare strings securely.
}
```

### Reconstructing a Secret

To reconstruct the secret using a sufficient number of (serialized) shares:

```csharp
// Assume you have collected at least 't' serialized shares
List<string> collectedSerializedShares = new List<string>
{
    // Example for a secret like "Hi" (bytes [72, 105]) split with t=2:
    "1:C4:A1", // Example for a share (X=1, YValues might be [196, 161] in hex)
    "2:B8:D3", // Example for another share (X=2, YValues might be [184, 211] in hex)
    // "3:AD:05"  // And another, if you collected more than t.
    // Note: These are illustrative. Actual values depend on the secret and the random polynomial generated.
    // For the "My Top Secret Data!" example, shares would be longer, e.g., "1:CD:D4:A8:C8:92:8E:A8:B7:9A:A6:8E:A1:9A:A8:B1:A3:A6:8C"
};

List<Share> sharesForReconstruction = new List<Share>();
foreach (string serializedShare in collectedSerializedShares)
{
    try
    {
        sharesForReconstruction.Add(Share.Parse(serializedShare));
    }
    catch (FormatException ex)
    {
        Console.WriteLine($"Error parsing share string \"{serializedShare}\": {ex.Message}");
        // Handle error: skip share, log, or terminate
        continue;
    }
    catch (ArgumentNullException ex)
    {
        Console.WriteLine($"Error parsing share string: {ex.Message}"); // For null/empty string
        continue;
    }
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
        Console.WriteLine($"Reconstruction failed: {ex.Message}"); // e.g., not enough distinct shares, or inconsistent YValue lengths
    }
}
else
{
    Console.WriteLine("Not enough successfully parsed shares to reconstruct the secret.");
}
```

### Share Serialization

The `Share` record provides methods for serialization:
-   `share.ToString()`: Converts a `Share` object to a string where the X-coordinate and all Y-values are represented in hexadecimal format, delimited by colons (e.g., `X_hex:Y0_hex:Y1_hex:...`). For instance, a share with `X=10` and `YValues=[255, 1, 16]` would be serialized as `"A:FF:1:10"`.
-   `Share.Parse(string s)`: Converts a serialized string (in the format produced by `ToString()`) back into a `Share` object. It throws `ArgumentNullException` if the string is null/empty or `FormatException` if the string is malformed or contains invalid hexadecimal values.

### Prime Number (`_field.Prime`)

-   The default prime used is 257. This is suitable for splitting `byte[]` secrets, as each byte (0-255) can be a field element.
-   The prime must be greater than the maximum value of an individual element of your secret and also greater than `n` (the total number of shares).
-   You can specify a custom prime in the `ShamirSecretSharingService` constructor if needed, but ensure your secret data and `n` are compatible.

## Security Considerations

-   **Randomness:** The security of SSS relies on the cryptographic randomness of the coefficients chosen for the polynomial. This implementation uses `System.Security.Cryptography.RandomNumberGenerator` for this purpose, with improved unbiased generation for coefficients.
-   **Share Security:** Each individual share must be kept secret. If an attacker obtains `t` or more shares, they can reconstruct the secret. SSS protects against the loss/compromise of *up to* `t-1` shares.
-   **Integrity/Authenticity:** This basic SSS implementation does not inherently protect against malicious shares (a participant providing a fake or altered share during reconstruction). For such scenarios, Verifiable Secret Sharing (VSS) schemes are needed.
-   **Side Channels:** As with any cryptographic implementation, consider potential side-channel attacks depending on the environment where share generation or reconstruction occurs.

## Limitations

-   The current implementation is primarily optimized for `byte[]` secrets using GF(257). Adapting it for secrets composed of larger data types (e.g., `int` arrays) would require adjusting the prime and potentially the `YValues` storage in the `Share` record.
-   The maximum number of shares (`n`) is limited by `Prime - 1`. For the default prime 257, `n` can be at most 256.

## Project Structure

-   `ShamirSecretSharing/FiniteField.cs`: Implements arithmetic operations in a Galois Field GF(p).
-   `ShamirSecretSharing/Share.cs`: Defines the `Share` record and its serialization/deserialization logic.
-   `ShamirSecretSharing/ShamirSecretSharingService.cs`: Contains the core logic for splitting and reconstructing secrets.
-   `ShamirSecretSharingTests/` (Separate Project): Contains MSTest unit tests.
-   `ShamirSecretSharing.Console/` (Separate Project): Contains a console application for testing the library interactively.

## Building and Testing

1.  Open the solution in Visual Studio or use the .NET CLI.
2.  Build the solution: `dotnet build`
3.  Run tests (from the solution directory or test project directory): `dotnet test`