using System.Security.Cryptography;

namespace ShamirSecretSharing;

/// <summary>
/// Cryptographic <see cref="RandomSource"/> backed by
/// <see cref="RandomNumberGenerator"/>. The production adapter.
/// </summary>
public sealed class CryptoRandomSource : RandomSource
{
    /// <summary>Gets the shared singleton instance.</summary>
    public static CryptoRandomSource Instance { get; } = new();

    private CryptoRandomSource() { }

    /// <inheritdoc/>
    public override void GetBytes(Span<byte> destination) =>
        RandomNumberGenerator.Fill(destination);

    /// <inheritdoc/>
    public override void GetInts(Span<int> destination, int exclusiveUpperBound)
    {
        // Explicit so the bound is rejected even when destination is empty —
        // matches the contract of the base method; the BCL call below would
        // otherwise skip validation in that case.
        ArgumentOutOfRangeException.ThrowIfLessThan(exclusiveUpperBound, 1);
        for (var i = 0; i < destination.Length; i++)
            destination[i] = RandomNumberGenerator.GetInt32(exclusiveUpperBound);
    }
}
