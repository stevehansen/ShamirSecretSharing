namespace ShamirSecretSharing;

/// <summary>
/// Thrown when one or more shares fail authentication during
/// <see cref="AuthenticatedSecretCombiner.Combine"/>. The secret is never
/// disclosed when this exception is thrown.
/// </summary>
public sealed class ShareAuthenticationException : Exception
{
    /// <summary>Initializes a new instance with no message.</summary>
    public ShareAuthenticationException()
    {
    }

    /// <summary>Initializes a new instance with the given message.</summary>
    /// <param name="message">A human-readable description of the failure.</param>
    public ShareAuthenticationException(string message) : base(message)
    {
    }

    /// <summary>Initializes a new instance with the given message and inner exception.</summary>
    /// <param name="message">A human-readable description of the failure.</param>
    /// <param name="inner">The underlying exception that triggered this failure.</param>
    public ShareAuthenticationException(string message, Exception inner) : base(message, inner)
    {
    }

    /// <summary>
    /// X-coordinates of the shares that failed verification. Empty when the
    /// failure cannot be attributed to a specific share.
    /// </summary>
    public IReadOnlyList<int> OffendingShareXs { get; init; } = Array.Empty<int>();
}
