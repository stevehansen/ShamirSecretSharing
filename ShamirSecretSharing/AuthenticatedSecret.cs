namespace ShamirSecretSharing;

/// <summary>
/// Shared constants for the authenticated split/combine pair. Centralising the
/// constraint here prevents the splitter and combiner from drifting apart.
/// </summary>
internal static class AuthenticatedSecret
{
    /// <summary>
    /// Smallest field prime accepted by <see cref="AuthenticatedSecretSplitter"/>
    /// and <see cref="AuthenticatedSecretCombiner"/>. The recursively-split issue
    /// key is sampled as raw bytes (range 0..255); any prime smaller than 256
    /// would reject a byte from the key with overwhelming probability, so we
    /// reject the configuration loudly at construction instead.
    /// </summary>
    public const int MinimumPrime = 256;
}
