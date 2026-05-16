using System.Text;

namespace ShamirSecretSharing;

/// <summary>
/// Provides functionality for Shamir's Secret Sharing scheme, allowing splitting
/// and reconstructing secrets using threshold cryptography.
/// </summary>
/// <remarks>
/// Shamir's Secret Sharing is a cryptographic algorithm that splits a secret into
/// <c>n</c> shares, any <c>t</c> of which can reconstruct the original secret.
/// This implementation performs arithmetic in a finite field GF(p), where p is a
/// prime number (default 257, suitable for byte values 0-255).
/// </remarks>
public class ShamirSecretSharingService
{
    private readonly FiniteField _field;
    private const int DefaultPrime = 257; // Smallest prime > 255
    private const int StackallocThreshold = 256;

    /// <summary>
    /// Initializes a new instance of the <see cref="ShamirSecretSharingService"/> class.
    /// </summary>
    /// <param name="prime">The prime modulus to use for the finite field. Defaults to 257.</param>
    /// <remarks>
    /// The prime must be greater than any single value in the secret and greater than
    /// the total shares <c>n</c> you intend to produce. For byte-array secrets, the
    /// default of 257 is suitable as it's the smallest prime greater than 255.
    /// </remarks>
    public ShamirSecretSharingService(int prime = DefaultPrime)
    {
        _field = new(prime);
    }

    /// <summary>
    /// Splits a secret byte array into n shares, with t shares required for reconstruction.
    /// </summary>
    /// <param name="secret">The secret data to split.</param>
    /// <param name="n">The total shares to produce. Must satisfy <c>t &lt;= n &lt; Prime</c>.</param>
    /// <param name="t">The threshold of shares required to reconstruct the secret.</param>
    /// <returns>An array of n shares.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when secret is null or empty, or when a secret byte value is too large for the chosen prime.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when t is less than or equal to 1, n is less than t, or n is greater than or equal to the prime modulus.
    /// </exception>
    public Share[] SplitSecret(byte[] secret, int n, int t)
    {
        if (secret == null || secret.Length == 0)
            throw new ArgumentException("Secret cannot be null or empty.", nameof(secret));
        if (t <= 1)
            throw new ArgumentOutOfRangeException(nameof(t), "Threshold t must be greater than 1.");
        if (n < t)
            throw new ArgumentOutOfRangeException(nameof(n), "Total shares n must be greater than or equal to threshold t.");
        if (n >= _field.Prime)
            // X-coordinates must be < Prime. We use 1 to n. So n must be < Prime.
            throw new ArgumentOutOfRangeException(nameof(n), $"Total shares n must be less than the prime modulus ({_field.Prime}).");

        var yValuesPerShare = new int[n][];
        for (var i = 0; i < n; i++)
            yValuesPerShare[i] = new int[secret.Length];

        var xs = new int[n];
        for (var i = 0; i < n; i++)
            xs[i] = i + 1;

        Span<int> ys = n <= StackallocThreshold ? stackalloc int[n] : new int[n];
        for (var byteIndex = 0; byteIndex < secret.Length; byteIndex++)
        {
            var secretByte = secret[byteIndex];
            if (secretByte >= _field.Prime)
                throw new ArgumentException($"Secret byte value {secretByte} at index {byteIndex} is too large for the chosen prime {_field.Prime}.");

            SecretPolynomial.SampleAndEvaluate(secretByte, t, xs, ys, _field);
            for (var i = 0; i < n; i++)
                yValuesPerShare[i][byteIndex] = ys[i];
        }

        var shares = new Share[n];
        for (var i = 0; i < n; i++)
            shares[i] = new(xs[i], yValuesPerShare[i]);

        return shares;
    }

    /// <summary>
    /// Reconstructs the secret from a list of shares.
    /// </summary>
    /// <param name="shares">A list of at least t shares.</param>
    /// <param name="t">The original threshold used when splitting.</param>
    /// <returns>The reconstructed secret byte array.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the shares list is null or empty, contains fewer than t shares,
    /// contains shares with YValues of different lengths, or does not contain enough distinct shares.
    /// </exception>
    public byte[] ReconstructSecret(IReadOnlyList<Share> shares, int t)
    {
        if (shares == null || shares.Count == 0)
            throw new ArgumentException("Shares list cannot be null or empty.", nameof(shares));
        if (shares.Count < t)
            throw new ArgumentException($"Not enough shares provided to reconstruct. Need {t}, got {shares.Count}.", nameof(shares));

        // Ensure all shares have the same YValues length
        var secretLength = shares[0].YValues.Length;
        if (shares.Any(s => s.YValues.Length != secretLength))
            throw new ArgumentException("All shares must have YValues of the same length.");
        if (secretLength == 0)
            return []; // Or throw, depending on desired behavior for empty secret

        // Take only t shares if more are provided, and check for distinct X values
        var distinctShares = shares.GroupBy(s => s.X).Select(g => g.First()).Take(t).ToList();
        if (distinctShares.Count < t)
            throw new ArgumentException($"Not enough distinct shares provided. Need {t} distinct X values, got {distinctShares.Count}.", nameof(shares));

        var xs = new int[t];
        for (var i = 0; i < t; i++)
            xs[i] = distinctShares[i].X;

        var basis = SecretPolynomial.ComputeLagrangeBasisAtZero(xs, _field);
        var reconstructedSecret = new byte[secretLength];
        Span<int> ys = t <= StackallocThreshold ? stackalloc int[t] : new int[t];

        for (var byteIndex = 0; byteIndex < secretLength; byteIndex++)
        {
            for (var i = 0; i < t; i++)
                ys[i] = distinctShares[i].YValues[byteIndex];

            reconstructedSecret[byteIndex] = (byte)SecretPolynomial.InterpolateWithBasis(ys, basis, _field);
        }
        return reconstructedSecret;
    }

    /// <summary>
    /// Splits a secret string into n shares, with t shares required for reconstruction.
    /// </summary>
    /// <param name="secret">The secret string to split.</param>
    /// <param name="n">The total shares to produce. Must satisfy <c>t &lt;= n &lt; Prime</c>.</param>
    /// <param name="t">The threshold of shares required to reconstruct the secret.</param>
    /// <param name="encoding">The encoding to use for converting the string to bytes. Defaults to UTF-8.</param>
    /// <returns>An array of n shares.</returns>
    /// <exception cref="ArgumentException">Thrown if the secret is null or empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if t or n are invalid.</exception>
    public Share[] SplitSecret(string secret, int n, int t, Encoding? encoding = null)
    {
        encoding ??= Encoding.UTF8;
        return SplitSecret(encoding.GetBytes(secret), n, t);
    }

    /// <summary>
    /// Reconstructs a secret string from a list of shares.
    /// </summary>
    /// <param name="shares">A list of at least t shares.</param>
    /// <param name="t">The original threshold used when splitting.</param>
    /// <param name="encoding">The encoding to use for converting bytes back to a string. Defaults to UTF-8.</param>
    /// <returns>The reconstructed secret string.</returns>
    /// <exception cref="ArgumentException">Thrown if the shares list is invalid.</exception>
    public string ReconstructSecretString(IReadOnlyList<Share> shares, int t, Encoding? encoding = null)
    {
        encoding ??= Encoding.UTF8;
        var reconstructedBytes = ReconstructSecret(shares, t);
        return encoding.GetString(reconstructedBytes);
    }
}
