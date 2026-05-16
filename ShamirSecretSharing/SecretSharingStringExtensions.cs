using System.Text;

namespace ShamirSecretSharing;

/// <summary>
/// String-oriented convenience extensions over <see cref="SecretSplitter"/> and <see cref="SecretCombiner"/>.
/// </summary>
public static class SecretSharingStringExtensions
{
    /// <summary>
    /// Splits a secret string into <paramref name="n"/> shares, with <paramref name="t"/>
    /// shares required for reconstruction.
    /// </summary>
    /// <param name="splitter">The splitter to delegate to.</param>
    /// <param name="secret">The secret string to split.</param>
    /// <param name="n">The total shares to produce. Must satisfy <c>t &lt;= n &lt; Prime</c>.</param>
    /// <param name="t">The threshold of shares required to reconstruct the secret.</param>
    /// <param name="encoding">The encoding to use for converting the string to bytes. Defaults to UTF-8.</param>
    /// <returns>An array of <paramref name="n"/> shares.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="splitter"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if the secret is null or empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="n"/> or <paramref name="t"/> are invalid.</exception>
    public static Share[] Split(this SecretSplitter splitter, string secret, int n, int t, Encoding? encoding = null)
    {
        ArgumentNullException.ThrowIfNull(splitter);
        encoding ??= Encoding.UTF8;
        return splitter.Split(encoding.GetBytes(secret), n, t);
    }

    /// <summary>
    /// Reconstructs a secret string from the supplied shares.
    /// </summary>
    /// <param name="combiner">The combiner to delegate to.</param>
    /// <param name="shares">The shares to interpolate.</param>
    /// <param name="encoding">The encoding to use for converting bytes back to a string. Defaults to UTF-8.</param>
    /// <returns>The reconstructed secret string.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="combiner"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if the shares list is invalid.</exception>
    public static string CombineString(this SecretCombiner combiner, IReadOnlyList<Share> shares, Encoding? encoding = null)
    {
        ArgumentNullException.ThrowIfNull(combiner);
        encoding ??= Encoding.UTF8;
        return encoding.GetString(combiner.Combine(shares));
    }
}
