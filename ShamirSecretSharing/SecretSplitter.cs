namespace ShamirSecretSharing;

/// <summary>
/// Splits a secret into shares using Shamir's Secret Sharing scheme.
/// </summary>
/// <remarks>
/// Each byte of the secret is treated as an independent element of GF(<c>prime</c>);
/// a fresh degree-(<c>threshold</c>-1) polynomial is sampled per byte and evaluated
/// at <c>x = 1..shareCount</c>.
/// </remarks>
public sealed class SecretSplitter
{
    private readonly FiniteField _field;
    private readonly RandomSource _random;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretSplitter"/> class
    /// backed by <see cref="CryptoRandomSource"/>.
    /// </summary>
    /// <param name="prime">The prime modulus to use for the finite field. Defaults to 257.</param>
    /// <remarks>
    /// The prime must be greater than any single value in the secret. For byte-array
    /// secrets, the default of 257 is suitable as it's the smallest prime greater than
    /// 255. It also caps the per-call <c>shareCount</c> at <c>prime - 1</c>.
    /// </remarks>
    public SecretSplitter(int prime = FiniteField.DefaultPrime)
        : this(prime, CryptoRandomSource.Instance)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretSplitter"/> class with
    /// an explicit <see cref="RandomSource"/>.
    /// </summary>
    /// <param name="prime">The prime modulus to use for the finite field.</param>
    /// <param name="randomSource">Source of random field elements. Use <see cref="CryptoRandomSource.Instance"/> for production.</param>
    public SecretSplitter(int prime, RandomSource randomSource)
    {
        _field = prime == FiniteField.DefaultPrime ? FiniteField.Default : new FiniteField(prime);
        _random = randomSource;
    }

    /// <summary>
    /// Splits a secret into <paramref name="shareCount"/> shares, with
    /// <paramref name="threshold"/> shares required for reconstruction.
    /// </summary>
    /// <param name="secret">The secret data to split.</param>
    /// <param name="shareCount">The total shares to produce. Must satisfy <c>threshold &lt;= shareCount &lt; Prime</c>.</param>
    /// <param name="threshold">The threshold of shares required to reconstruct the secret.</param>
    /// <returns>An array of <paramref name="shareCount"/> shares.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the secret is empty, or when a secret byte value is too large for the chosen prime.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when threshold is less than or equal to 1, shareCount is less than threshold, or shareCount is greater than or equal to the prime modulus.
    /// </exception>
    public Share[] Split(ReadOnlySpan<byte> secret, int shareCount, int threshold)
    {
        if (secret.Length == 0)
            throw new ArgumentException("Secret cannot be empty.", nameof(secret));
        if (threshold <= 1)
            throw new ArgumentOutOfRangeException(nameof(threshold), "Threshold t must be greater than 1.");
        if (shareCount < threshold)
            throw new ArgumentOutOfRangeException(nameof(shareCount), "Total shares n must be greater than or equal to threshold t.");
        if (shareCount >= _field.Prime)
            // X-coordinates must be < Prime. We use 1 to shareCount. So shareCount must be < Prime.
            throw new ArgumentOutOfRangeException(nameof(shareCount), $"Total shares n must be less than the prime modulus ({_field.Prime}).");

        var yValuesPerShare = new int[shareCount][];
        for (var i = 0; i < shareCount; i++)
            yValuesPerShare[i] = new int[secret.Length];

        // One combined buffer for xs (first half) and ys (second half); same
        // stack/heap threshold as before — when each half fits, the combined
        // 2*shareCount stackalloc fits too.
        Span<int> xsYs = shareCount <= FiniteField.StackallocThreshold ? stackalloc int[shareCount * 2] : new int[shareCount * 2];
        var xs = xsYs[..shareCount];
        var ys = xsYs[shareCount..];
        for (var i = 0; i < shareCount; i++)
            xs[i] = i + 1;
        for (var byteIndex = 0; byteIndex < secret.Length; byteIndex++)
        {
            var secretByte = secret[byteIndex];
            if (secretByte >= _field.Prime)
                throw new ArgumentException($"Secret byte value {secretByte} at index {byteIndex} is too large for the chosen prime {_field.Prime}.");

            SecretPolynomial.SampleAndEvaluate(secretByte, threshold, xs, ys, _field, _random);
            for (var i = 0; i < shareCount; i++)
                yValuesPerShare[i][byteIndex] = ys[i];
        }

        var shares = new Share[shareCount];
        for (var i = 0; i < shareCount; i++)
            shares[i] = new(xs[i], yValuesPerShare[i]);

        return shares;
    }
}
