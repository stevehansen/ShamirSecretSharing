using System.Buffers.Binary;
using System.Numerics;

namespace ShamirSecretSharing;

/// <summary>
/// Source of cryptographically strong random bytes used by the splitters.
/// </summary>
/// <remarks>
/// This is a trust boundary: a weak or predictable implementation breaks the
/// scheme's secrecy guarantee. Production code uses <see cref="CryptoRandomSource"/>;
/// other implementations exist for deterministic testing or future HSM / audit routing.
/// </remarks>
public abstract class RandomSource
{
    /// <summary>
    /// Gets the default cryptographic source. Same instance as
    /// <see cref="CryptoRandomSource.Instance"/>.
    /// </summary>
    public static RandomSource Default => CryptoRandomSource.Instance;

    /// <summary>
    /// Fills <paramref name="destination"/> with cryptographically random bytes.
    /// </summary>
    /// <param name="destination">The buffer to fill.</param>
    public abstract void GetBytes(Span<byte> destination);

    /// <summary>
    /// Fills <paramref name="destination"/> with integers uniformly distributed in
    /// <c>[0, exclusiveUpperBound)</c>.
    /// </summary>
    /// <param name="destination">The buffer to fill.</param>
    /// <param name="exclusiveUpperBound">The exclusive upper bound. Must be at least 1.</param>
    /// <remarks>
    /// The default implementation derives values from <see cref="GetBytes"/> using
    /// unbiased rejection sampling over 4-byte windows. Production adapters may
    /// override to call a tuned primitive directly.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="exclusiveUpperBound"/> is less than 1.
    /// </exception>
    public virtual void GetInts(Span<int> destination, int exclusiveUpperBound)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(exclusiveUpperBound, 1);

        var mask = (uint)BitOperations.RoundUpToPowerOf2((uint)exclusiveUpperBound) - 1;
        Span<byte> buf = stackalloc byte[4];
        for (var i = 0; i < destination.Length; i++)
        {
            uint candidate;
            do
            {
                GetBytes(buf);
                // Explicit little-endian read so script-replay adapters (e.g.
                // SequenceRandomSource) yield identical sequences on BE hosts.
                candidate = BinaryPrimitives.ReadUInt32LittleEndian(buf) & mask;
            }
            while (candidate >= (uint)exclusiveUpperBound);
            destination[i] = (int)candidate;
        }
    }
}
