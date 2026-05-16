namespace ShamirSecretSharing;

/// <summary>
/// Combines shares produced by <see cref="SecretSplitter"/> to reconstruct the original secret.
/// </summary>
/// <remarks>
/// The caller is responsible for supplying exactly the shares to interpolate.
/// All shares passed in are used; the combiner does not truncate or dedupe.
/// </remarks>
public sealed class SecretCombiner
{
    private readonly FiniteField _field;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretCombiner"/> class.
    /// </summary>
    /// <param name="prime">The prime modulus to use for the finite field. Defaults to 257.</param>
    /// <remarks>
    /// The prime must match the value used when the shares were produced.
    /// </remarks>
    public SecretCombiner(int prime = FiniteField.DefaultPrime)
    {
        _field = new(prime);
    }

    /// <summary>
    /// Reconstructs the secret from the supplied shares.
    /// </summary>
    /// <param name="shares">The shares to interpolate. Every share is used; X coordinates must be distinct.</param>
    /// <returns>The reconstructed secret byte array.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="shares"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when the shares list is empty, contains shares with YValues of different lengths,
    /// or contains duplicate X coordinates.
    /// </exception>
    public byte[] Combine(IReadOnlyList<Share> shares)
    {
        ArgumentNullException.ThrowIfNull(shares);
        if (shares.Count == 0)
            throw new ArgumentException("Shares list cannot be empty.", nameof(shares));

        var secretLength = shares[0].YValues.Length;
        if (shares.Any(s => s.YValues.Length != secretLength))
            throw new ArgumentException("All shares must have YValues of the same length.");
        if (secretLength == 0)
            return [];

        var count = shares.Count;
        var distinctXs = new HashSet<int>(count);
        for (var i = 0; i < count; i++)
        {
            if (!distinctXs.Add(shares[i].X))
                throw new ArgumentException("Shares must have distinct X coordinates.", nameof(shares));
        }

        Span<int> xs = count <= FiniteField.StackallocThreshold ? stackalloc int[count] : new int[count];
        for (var i = 0; i < count; i++)
            xs[i] = shares[i].X;

        var basis = SecretPolynomial.ComputeLagrangeBasisAtZero(xs, _field);
        var reconstructedSecret = new byte[secretLength];
        Span<int> ys = count <= FiniteField.StackallocThreshold ? stackalloc int[count] : new int[count];

        for (var byteIndex = 0; byteIndex < secretLength; byteIndex++)
        {
            for (var i = 0; i < count; i++)
                ys[i] = shares[i].YValues[byteIndex];

            reconstructedSecret[byteIndex] = (byte)SecretPolynomial.InterpolateWithBasis(ys, basis, _field);
        }
        return reconstructedSecret;
    }
}
