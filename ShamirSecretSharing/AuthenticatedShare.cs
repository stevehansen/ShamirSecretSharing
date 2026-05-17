using System.Globalization;
using System.Text;

namespace ShamirSecretSharing;

/// <summary>
/// An authenticated Shamir share. Carries the secret share, the matching
/// fragment of the per-issue MAC key, a truncated HMAC tag, and a 4-byte
/// issue identifier. Immutable; round-trips through <see cref="ToString"/>
/// and <see cref="Parse"/>.
/// </summary>
public sealed record AuthenticatedShare
{
    /// <summary>Length in bytes of the truncated HMAC tag carried on every share.</summary>
    internal const int TagLength = 16;

    /// <summary>Length in bytes of the issue identifier carried on every share.</summary>
    internal const int IssueIdLength = 4;

    private readonly byte[] _tag;
    private readonly byte[] _issueId;

    /// <summary>
    /// Initializes a new instance. Typical callers obtain instances from
    /// <see cref="AuthenticatedSecretSplitter.Split"/> or <see cref="Parse"/>
    /// rather than constructing them directly.
    /// </summary>
    /// <param name="share">The secret share. Its <see cref="Share.X"/> must equal <paramref name="keyShare"/>'s X.</param>
    /// <param name="keyShare">The per-share fragment of the issue MAC key.</param>
    /// <param name="tag">The truncated HMAC tag (16 bytes).</param>
    /// <param name="issueId">The issue identifier (4 bytes).</param>
    /// <exception cref="ArgumentNullException">Thrown when any argument is null.</exception>
    /// <exception cref="ArgumentException">Thrown when X-coordinates disagree or buffer lengths are wrong.</exception>
    public AuthenticatedShare(Share share, Share keyShare, byte[] tag, byte[] issueId)
    {
        ArgumentNullException.ThrowIfNull(share);
        ArgumentNullException.ThrowIfNull(keyShare);
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(issueId);
        if (share.X != keyShare.X)
            throw new ArgumentException($"Secret share and key share must share the same X coordinate (secret={share.X}, key={keyShare.X}).", nameof(keyShare));
        if (tag.Length != TagLength)
            throw new ArgumentException($"Tag must be exactly {TagLength} bytes (got {tag.Length}).", nameof(tag));
        if (issueId.Length != IssueIdLength)
            throw new ArgumentException($"IssueId must be exactly {IssueIdLength} bytes (got {issueId.Length}).", nameof(issueId));

        Share = share;
        KeyShare = keyShare;
        _tag = (byte[])tag.Clone();
        _issueId = (byte[])issueId.Clone();
    }

    /// <summary>The secret share. Its X coordinate matches <see cref="KeyShare"/>'s X.</summary>
    public Share Share { get; }

    /// <summary>The per-share fragment of the recursively-split issue key.</summary>
    public Share KeyShare { get; }

    /// <summary>A defensive copy of the 16-byte truncated HMAC tag.</summary>
    public byte[] Tag => (byte[])_tag.Clone();

    /// <summary>A defensive copy of the 4-byte issue identifier.</summary>
    public byte[] IssueId => (byte[])_issueId.Clone();

    /// <summary>Internal accessor that avoids the defensive clone for hot paths inside the library.</summary>
    internal ReadOnlySpan<byte> TagSpan => _tag;

    /// <summary>Internal accessor that avoids the defensive clone for hot paths inside the library.</summary>
    internal ReadOnlySpan<byte> IssueIdSpan => _issueId;

    /// <summary>
    /// Serializes to a compact single-line string of the form
    /// <c>&lt;secret-share&gt;|&lt;key-share&gt;|&lt;hex-tag&gt;&lt;hex-issueid&gt;</c>,
    /// where each inner share uses <see cref="Share.ToString"/> and the trailer is
    /// uppercase hex.
    /// </summary>
    /// <returns>The wire form.</returns>
    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.Append(Share.ToString());
        sb.Append('|');
        sb.Append(KeyShare.ToString());
        sb.Append('|');
        AppendHex(sb, _tag);
        AppendHex(sb, _issueId);
        return sb.ToString();
    }

    /// <summary>
    /// Parses the wire form produced by <see cref="ToString"/>. Does not perform
    /// authentication; pass the result to <see cref="AuthenticatedSecretCombiner.Combine"/>
    /// to verify.
    /// </summary>
    /// <param name="serialized">The wire form.</param>
    /// <returns>The reconstructed <see cref="AuthenticatedShare"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="serialized"/> is null or empty.</exception>
    /// <exception cref="FormatException">Thrown when the input is not a well-formed authenticated share.</exception>
    public static AuthenticatedShare Parse(string serialized)
    {
        if (string.IsNullOrEmpty(serialized))
            throw new ArgumentNullException(nameof(serialized));

        var parts = serialized.Split('|');
        if (parts.Length != 3)
            throw new FormatException($"Authenticated share must contain exactly two '|' separators (got {parts.Length - 1}).");

        Share secretShare;
        Share keyShare;
        try
        {
            secretShare = Share.Parse(parts[0]);
            keyShare = Share.Parse(parts[1]);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            throw new FormatException("Inner share segment is malformed.", ex);
        }

        var trailer = parts[2];
        const int expectedTrailerHexLength = (TagLength + IssueIdLength) * 2;
        if (trailer.Length != expectedTrailerHexLength)
            throw new FormatException($"Trailer must be exactly {expectedTrailerHexLength} hex characters (got {trailer.Length}).");

        var tag = ParseHex(trailer.AsSpan(0, TagLength * 2));
        var issueId = ParseHex(trailer.AsSpan(TagLength * 2, IssueIdLength * 2));

        return new AuthenticatedShare(secretShare, keyShare, tag, issueId);
    }

    private static void AppendHex(StringBuilder sb, byte[] bytes)
    {
        for (var i = 0; i < bytes.Length; i++)
            sb.Append(bytes[i].ToString("X2", CultureInfo.InvariantCulture));
    }

    private static byte[] ParseHex(ReadOnlySpan<char> hex)
    {
        if ((hex.Length & 1) != 0)
            throw new FormatException("Hex segment must have an even number of characters.");
        var bytes = new byte[hex.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            if (!byte.TryParse(hex.Slice(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
                throw new FormatException($"Invalid hex byte '{hex.Slice(i * 2, 2).ToString()}' in authenticated share trailer.");
            bytes[i] = b;
        }
        return bytes;
    }
}
