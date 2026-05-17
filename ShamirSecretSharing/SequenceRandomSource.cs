namespace ShamirSecretSharing;

/// <summary>
/// Deterministic <see cref="RandomSource"/> that replays a fixed byte script.
/// Intended for tests and golden-vector reproduction; not safe for production use.
/// </summary>
/// <remarks>
/// Does not override <see cref="RandomSource.GetInts"/>: the base-class
/// rejection sampler drives both polynomial coefficient streams and HMAC key
/// material from a single ordered byte transcript. Not thread-safe;
/// construct a fresh instance per test.
/// </remarks>
public sealed class SequenceRandomSource : RandomSource
{
    private readonly byte[] _script;
    private int _position;

    /// <summary>
    /// Initializes a new instance that replays <paramref name="script"/>.
    /// </summary>
    /// <param name="script">The byte script to replay. Copied internally.</param>
    public SequenceRandomSource(ReadOnlySpan<byte> script)
    {
        _script = script.ToArray();
    }

    /// <inheritdoc/>
    public override void GetBytes(Span<byte> destination)
    {
        if (_position + destination.Length > _script.Length)
            throw new InvalidOperationException(
                $"SequenceRandomSource script exhausted: requested {destination.Length} byte(s) at position {_position}, script length is {_script.Length}.");

        _script.AsSpan(_position, destination.Length).CopyTo(destination);
        _position += destination.Length;
    }
}
