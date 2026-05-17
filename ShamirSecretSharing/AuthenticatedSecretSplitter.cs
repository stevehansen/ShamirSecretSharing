using System.Security.Cryptography;
using System.Text;

namespace ShamirSecretSharing;

/// <summary>
/// Splits a secret into integrity-protected shares. Each produced share carries a
/// per-share HMAC-SHA256 tag keyed by a freshly generated 256-bit issue key; the
/// issue key is itself Shamir-split across the same shares, so reconstruction
/// re-derives the verification key without any caller-managed secret.
/// </summary>
/// <remarks>
/// Defeats per-share modification in storage or transit (STRIDE T-01) provided
/// the verifier collects at least one un-tampered share. Does NOT defend against
/// a dishonest dealer (STRIDE S-01) or against an attacker who controls the full
/// delivery channel and replaces every share with a self-consistent forgery.
/// </remarks>
public sealed class AuthenticatedSecretSplitter
{
    private const int IssueKeyLength = 32;
    private static readonly byte[] IssueIdLabel = Encoding.ASCII.GetBytes("issue");

    private readonly SecretSplitter _inner;

    /// <summary>
    /// Initializes a new splitter using the default finite field GF(257).
    /// </summary>
    public AuthenticatedSecretSplitter() : this(FiniteField.DefaultPrime)
    {
    }

    /// <summary>
    /// Initializes a new splitter with an explicit field prime. Must match the combiner.
    /// </summary>
    /// <param name="prime">Finite-field prime. Must be at least <see cref="AuthenticatedSecret.MinimumPrime"/> so the recursively-split 32-byte issue key (bytes 0..255) always fits in the field.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="prime"/> is less than <see cref="AuthenticatedSecret.MinimumPrime"/>.</exception>
    public AuthenticatedSecretSplitter(int prime)
    {
        if (prime < AuthenticatedSecret.MinimumPrime)
            throw new ArgumentOutOfRangeException(nameof(prime), prime, $"Authenticated split requires prime >= {AuthenticatedSecret.MinimumPrime} so the recursively-split issue key always fits in the field.");
        _inner = new SecretSplitter(prime);
    }

    /// <summary>
    /// Splits <paramref name="secret"/> into <paramref name="shareCount"/> authenticated
    /// shares, any <paramref name="threshold"/> of which reconstruct the original.
    /// </summary>
    /// <param name="secret">The secret bytes. Must be non-empty.</param>
    /// <param name="shareCount">Total shares to produce. Must satisfy <c>2 &lt;= threshold &lt;= shareCount &lt; prime</c>.</param>
    /// <param name="threshold">Shares required to reconstruct.</param>
    /// <returns>An array of authenticated, opaque, serializable shares.</returns>
    /// <exception cref="ArgumentException">Thrown when the secret is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="shareCount"/> or <paramref name="threshold"/> are invalid.</exception>
    public AuthenticatedShare[] Split(ReadOnlySpan<byte> secret, int shareCount, int threshold)
    {
        // TODO(#12): switch to IFieldRandomSource when #12 lands
        var issueKey = new byte[IssueKeyLength];
        RandomNumberGenerator.Fill(issueKey);

        try
        {
            var issueIdFull = HMACSHA256.HashData(issueKey, IssueIdLabel);
            var issueId = new byte[AuthenticatedShare.IssueIdLength];
            Buffer.BlockCopy(issueIdFull, 0, issueId, 0, AuthenticatedShare.IssueIdLength);

            var secretShares = _inner.Split(secret, shareCount, threshold);
            var keyShares = _inner.Split(issueKey, shareCount, threshold);

            var result = new AuthenticatedShare[shareCount];
            for (var i = 0; i < shareCount; i++)
            {
                // Only the secret share is MAC'd; the key share is bound to the issue
                // implicitly because reconstructing it yields the verification key K,
                // which is then matched against IssueId. Including key-share bytes in
                // the MAC input would not strengthen this — and would prevent the
                // combiner from attributing key-share tampering, since K becomes wrong
                // before any per-share MAC check can identify the offender.
                var canonical = CanonicalShareBytes.Encode(secretShares[i]);
                var fullTag = HMACSHA256.HashData(issueKey, canonical);
                var tag = new byte[AuthenticatedShare.TagLength];
                Buffer.BlockCopy(fullTag, 0, tag, 0, AuthenticatedShare.TagLength);

                result[i] = new AuthenticatedShare(secretShares[i], keyShares[i], tag, issueId);
            }

            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(issueKey);
        }
    }
}
