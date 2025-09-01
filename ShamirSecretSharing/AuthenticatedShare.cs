using System.Globalization;
using System.Text;

namespace ShamirSecretSharing;

/// <summary>
/// Represents an authenticated share in Shamir's Secret Sharing scheme with integrity verification.
/// </summary>
/// <remarks>
/// This class wraps a regular Share with authentication metadata including a signature
/// for tamper detection and timestamps for temporal validity tracking.
/// </remarks>
public record AuthenticatedShare
{
    /// <summary>
    /// Gets the underlying share containing the actual secret share data.
    /// </summary>
    public Share Share { get; }

    /// <summary>
    /// Gets the cryptographic signature for verifying share integrity.
    /// </summary>
    public byte[] Signature { get; }

    /// <summary>
    /// Gets the timestamp when this share was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; }

    /// <summary>
    /// Gets the optional expiration timestamp for this share.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthenticatedShare"/> record.
    /// </summary>
    /// <param name="share">The underlying share data.</param>
    /// <param name="signature">The cryptographic signature for the share.</param>
    /// <param name="createdAt">The creation timestamp.</param>
    /// <param name="expiresAt">The optional expiration timestamp.</param>
    /// <exception cref="ArgumentNullException">Thrown if share or signature is null.</exception>
    public AuthenticatedShare(Share share, byte[] signature, DateTimeOffset createdAt, DateTimeOffset? expiresAt = null)
    {
        Share = share ?? throw new ArgumentNullException(nameof(share));
        Signature = signature ?? throw new ArgumentNullException(nameof(signature));
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    /// <summary>
    /// Determines whether this share has expired based on the current time.
    /// </summary>
    /// <returns>True if the share has expired; otherwise, false.</returns>
    public bool IsExpired() => IsExpiredAt(DateTimeOffset.UtcNow);

    /// <summary>
    /// Determines whether this share has expired at a specific point in time.
    /// </summary>
    /// <param name="atTime">The time to check expiration against.</param>
    /// <returns>True if the share has expired; otherwise, false.</returns>
    public bool IsExpiredAt(DateTimeOffset atTime) => ExpiresAt.HasValue && atTime > ExpiresAt.Value;

    /// <summary>
    /// Serializes the authenticated share to a string representation.
    /// Format: Share|Base64Signature|ISO8601CreatedAt[|ISO8601ExpiresAt]
    /// </summary>
    /// <returns>A string representation of the authenticated share.</returns>
    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.Append(Share.ToString());
        sb.Append('|');
        sb.Append(Convert.ToBase64String(Signature));
        sb.Append('|');
        sb.Append(CreatedAt.ToString("O", CultureInfo.InvariantCulture));
        
        if (ExpiresAt.HasValue)
        {
            sb.Append('|');
            sb.Append(ExpiresAt.Value.ToString("O", CultureInfo.InvariantCulture));
        }
        
        return sb.ToString();
    }

    /// <summary>
    /// Deserializes an authenticated share from its string representation.
    /// </summary>
    /// <param name="authenticatedShareString">The string representation of the authenticated share.</param>
    /// <returns>An <see cref="AuthenticatedShare"/> object.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="authenticatedShareString"/> is null or empty.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="authenticatedShareString"/> is not in the expected format.</exception>
    public static AuthenticatedShare Parse(string authenticatedShareString)
    {
        if (string.IsNullOrEmpty(authenticatedShareString))
            throw new ArgumentException("Authenticated share string cannot be null or empty.", nameof(authenticatedShareString));

        var parts = authenticatedShareString.Split('|');
        if (parts.Length < 3 || parts.Length > 4)
            throw new ArgumentException(
                "Authenticated share string must contain 3 or 4 parts separated by '|'.",
                nameof(authenticatedShareString));

        // Parse the share
        var share = Share.Parse(parts[0]);

        // Parse the signature
        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(parts[1]);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("Invalid signature format in authenticated share string.", nameof(authenticatedShareString), ex);
        }

        // Parse the creation timestamp
        if (!DateTimeOffset.TryParseExact(parts[2], "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var createdAt))
            throw new ArgumentException($"Invalid creation timestamp format: {parts[2]}", nameof(authenticatedShareString));

        // Parse the optional expiration timestamp
        DateTimeOffset? expiresAt = null;
        if (parts.Length == 4)
        {
            if (!DateTimeOffset.TryParseExact(parts[3], "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var expires))
                throw new ArgumentException($"Invalid expiration timestamp format: {parts[3]}", nameof(authenticatedShareString));
            expiresAt = expires;
        }

        return new AuthenticatedShare(share, signature, createdAt, expiresAt);
    }
}