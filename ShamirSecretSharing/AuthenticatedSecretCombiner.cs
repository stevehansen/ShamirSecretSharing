using System.Security.Cryptography;
using System.Text;

namespace ShamirSecretSharing;

/// <summary>
/// Verifies and reconstructs a secret from authenticated shares. Verification
/// runs before Lagrange interpolation; on failure no partial secret is exposed.
/// </summary>
public sealed class AuthenticatedSecretCombiner
{
    private static readonly byte[] IssueIdLabel = Encoding.ASCII.GetBytes("issue");

    private readonly SecretCombiner _inner;

    /// <summary>Initializes a new combiner using the default finite field GF(257).</summary>
    public AuthenticatedSecretCombiner() : this(FiniteField.DefaultPrime)
    {
    }

    /// <summary>Initializes a new combiner with an explicit field prime. Must match the splitter.</summary>
    /// <param name="prime">Finite-field prime. Must be at least <see cref="AuthenticatedSecret.MinimumPrime"/>; see <see cref="AuthenticatedSecretSplitter(int)"/>.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="prime"/> is less than <see cref="AuthenticatedSecret.MinimumPrime"/>.</exception>
    public AuthenticatedSecretCombiner(int prime)
    {
        if (prime < AuthenticatedSecret.MinimumPrime)
            throw new ArgumentOutOfRangeException(nameof(prime), prime, $"Authenticated combine requires prime >= {AuthenticatedSecret.MinimumPrime} to match the splitter contract.");
        _inner = new SecretCombiner(prime);
    }

    /// <summary>
    /// Reconstructs the secret from <paramref name="shares"/>. Re-derives the issue
    /// key from the share-carried key fragments, HMAC-verifies every share in
    /// constant time, then runs Lagrange interpolation.
    /// </summary>
    /// <param name="shares">At least <c>threshold</c> shares from one <see cref="AuthenticatedSecretSplitter.Split"/> call.</param>
    /// <returns>The reconstructed secret bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="shares"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="shares"/> is empty or contains duplicate X coordinates.</exception>
    /// <exception cref="ShareAuthenticationException">
    /// One or more shares failed authentication (tampered, forged, or originated
    /// from a different issue). Inspect <see cref="ShareAuthenticationException.OffendingShareXs"/>
    /// to identify the bad shares.
    /// </exception>
    public byte[] Combine(IReadOnlyList<AuthenticatedShare> shares)
    {
        ArgumentNullException.ThrowIfNull(shares);
        if (shares.Count == 0)
            throw new ArgumentException("Shares list cannot be empty.", nameof(shares));
        for (var i = 0; i < shares.Count; i++)
            ArgumentNullException.ThrowIfNull(shares[i]);

        var distinctXs = new HashSet<int>(shares.Count);
        for (var i = 0; i < shares.Count; i++)
        {
            if (!distinctXs.Add(shares[i].Share.X))
                throw new ArgumentException("Shares must have distinct X coordinates.", nameof(shares));
        }

        var secretLength = shares[0].Share.YValues.Length;
        for (var i = 1; i < shares.Count; i++)
        {
            if (shares[i].Share.YValues.Length != secretLength)
                throw new ArgumentException("All shares must have YValues of the same length.", nameof(shares));
        }

        var reference = shares[0].IssueIdSpan;
        var issueDissenters = new List<int>();
        for (var i = 1; i < shares.Count; i++)
        {
            if (!CryptographicOperations.FixedTimeEquals(shares[i].IssueIdSpan, reference))
                issueDissenters.Add(shares[i].Share.X);
        }
        if (issueDissenters.Count > 0)
        {
            throw new ShareAuthenticationException("shares come from different splits")
            {
                OffendingShareXs = issueDissenters,
            };
        }

        var keyShares = new Share[shares.Count];
        for (var i = 0; i < shares.Count; i++)
            keyShares[i] = shares[i].KeyShare;

        byte[] issueKey;
        try
        {
            issueKey = _inner.Combine(keyShares);
        }
        catch (ArgumentException ex)
        {
            throw new ShareAuthenticationException("issue key reconstruction failed", ex)
            {
                OffendingShareXs = CollectAllXs(shares),
            };
        }

        try
        {
            var expectedIssueId = HMACSHA256.HashData(issueKey, IssueIdLabel)
                .AsSpan(0, AuthenticatedShare.IssueIdLength);

            if (!CryptographicOperations.FixedTimeEquals(expectedIssueId, reference))
            {
                throw new ShareAuthenticationException("issue key reconstruction failed")
                {
                    OffendingShareXs = CollectAllXs(shares),
                };
            }

            var failingXs = new List<int>();
            Span<byte> expectedTagFull = stackalloc byte[32];
            for (var i = 0; i < shares.Count; i++)
            {
                var canonical = CanonicalShareBytes.Encode(shares[i].Share);
                if (!HMACSHA256.TryHashData(issueKey, canonical, expectedTagFull, out _))
                    throw new InvalidOperationException("HMAC-SHA256 hash buffer was unexpectedly too small.");

                if (!CryptographicOperations.FixedTimeEquals(
                        expectedTagFull[..AuthenticatedShare.TagLength],
                        shares[i].TagSpan))
                {
                    failingXs.Add(shares[i].Share.X);
                }
            }

            if (failingXs.Count > 0)
            {
                throw new ShareAuthenticationException("one or more shares failed MAC verification")
                {
                    OffendingShareXs = failingXs,
                };
            }

            var secretShares = new Share[shares.Count];
            for (var i = 0; i < shares.Count; i++)
                secretShares[i] = shares[i].Share;
            return _inner.Combine(secretShares);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(issueKey);
        }
    }

    private static int[] CollectAllXs(IReadOnlyList<AuthenticatedShare> shares)
    {
        var xs = new int[shares.Count];
        for (var i = 0; i < shares.Count; i++)
            xs[i] = shares[i].Share.X;
        return xs;
    }
}
