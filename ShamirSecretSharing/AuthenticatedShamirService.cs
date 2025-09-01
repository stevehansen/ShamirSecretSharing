using System.Text;

namespace ShamirSecretSharing;

/// <summary>
/// Provides authenticated Shamir's Secret Sharing functionality with tamper detection and temporal validity.
/// </summary>
/// <remarks>
/// This service extends the basic Shamir's Secret Sharing scheme by adding cryptographic signatures
/// to shares, enabling detection of tampered or corrupted shares before reconstruction.
/// </remarks>
public class AuthenticatedShamirService
{
    private readonly ShamirSecretSharingService _shamirService;
    private readonly IShareAuthenticator _authenticator;

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthenticatedShamirService"/> class.
    /// </summary>
    /// <param name="authenticator">The authenticator to use for signing and verifying shares.</param>
    /// <param name="prime">The prime modulus for the finite field (default: 257).</param>
    /// <exception cref="ArgumentNullException">Thrown if authenticator is null.</exception>
    public AuthenticatedShamirService(IShareAuthenticator authenticator, int prime = 257)
    {
        _authenticator = authenticator ?? throw new ArgumentNullException(nameof(authenticator));
        _shamirService = new ShamirSecretSharingService(prime);
    }

    /// <summary>
    /// Splits a secret byte array into authenticated shares with integrity protection.
    /// </summary>
    /// <param name="secret">The secret data to split.</param>
    /// <param name="n">The total number of shares to create.</param>
    /// <param name="t">The threshold of shares required to reconstruct the secret.</param>
    /// <param name="expiresIn">Optional duration after which shares expire.</param>
    /// <returns>An array of authenticated shares.</returns>
    /// <exception cref="ArgumentException">Thrown if the secret is invalid.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if n or t are invalid.</exception>
    public AuthenticatedShare[] SplitAuthenticatedSecret(byte[] secret, int n, int t, TimeSpan? expiresIn = null)
    {
        // Use the underlying service to split the secret
        var shares = _shamirService.SplitSecret(secret, n, t);
        
        var createdAt = DateTimeOffset.UtcNow;
        var expiresAt = expiresIn.HasValue ? createdAt.Add(expiresIn.Value) : (DateTimeOffset?)null;
        
        var authenticatedShares = new AuthenticatedShare[shares.Length];
        for (var i = 0; i < shares.Length; i++)
        {
            var signature = _authenticator.SignShare(shares[i], createdAt, expiresAt);
            authenticatedShares[i] = new AuthenticatedShare(shares[i], signature, createdAt, expiresAt);
        }
        
        return authenticatedShares;
    }

    /// <summary>
    /// Splits a secret string into authenticated shares with integrity protection.
    /// </summary>
    /// <param name="secret">The secret string to split.</param>
    /// <param name="n">The total number of shares to create.</param>
    /// <param name="t">The threshold of shares required to reconstruct the secret.</param>
    /// <param name="expiresIn">Optional duration after which shares expire.</param>
    /// <param name="encoding">The encoding to use (default: UTF-8).</param>
    /// <returns>An array of authenticated shares.</returns>
    public AuthenticatedShare[] SplitAuthenticatedSecret(string secret, int n, int t, TimeSpan? expiresIn = null, Encoding? encoding = null)
    {
        encoding ??= Encoding.UTF8;
        return SplitAuthenticatedSecret(encoding.GetBytes(secret), n, t, expiresIn);
    }

    /// <summary>
    /// Reconstructs the secret from authenticated shares after validating their integrity.
    /// </summary>
    /// <param name="authenticatedShares">The authenticated shares to use for reconstruction.</param>
    /// <param name="t">The threshold number of shares required.</param>
    /// <param name="validateExpiry">Whether to check if shares have expired (default: true).</param>
    /// <returns>The reconstructed secret as a byte array.</returns>
    /// <exception cref="ArgumentException">Thrown if shares are invalid, tampered, or expired.</exception>
    /// <exception cref="InvalidOperationException">Thrown if share validation fails.</exception>
    public byte[] ReconstructAuthenticatedSecret(IReadOnlyList<AuthenticatedShare> authenticatedShares, int t, bool validateExpiry = true)
    {
        if (authenticatedShares == null || authenticatedShares.Count == 0)
            throw new ArgumentException("Authenticated shares list cannot be null or empty.", nameof(authenticatedShares));
        
        if (authenticatedShares.Count < t)
            throw new ArgumentException($"Not enough shares provided. Need {t}, got {authenticatedShares.Count}.", nameof(authenticatedShares));

        // Validate all shares before reconstruction
        var validationResults = ValidateShares(authenticatedShares, validateExpiry);
        
        // Check if we have enough valid shares
        var validShares = validationResults
            .Where(r => r.IsValid && r.Share != null)
            .Select(r => r.Share!)
            .ToList();
        
        if (validShares.Count < t)
        {
            var invalidCount = validationResults.Count(r => !r.IsValid);
            var reasons = validationResults
                .Where(r => !r.IsValid)
                .Select(r => r.FailureReason)
                .Distinct()
                .ToList();
            
            throw new InvalidOperationException(
                $"Not enough valid shares for reconstruction. {invalidCount} shares failed validation. " +
                $"Reasons: {string.Join(", ", reasons)}");
        }

        // Extract the underlying shares for reconstruction
        var shares = validShares
            .Select(s => s.Share)
            .Take(t) // Only use the required threshold number
            .ToList();

        return _shamirService.ReconstructSecret(shares, t);
    }

    /// <summary>
    /// Reconstructs a secret string from authenticated shares.
    /// </summary>
    /// <param name="authenticatedShares">The authenticated shares to use for reconstruction.</param>
    /// <param name="t">The threshold number of shares required.</param>
    /// <param name="validateExpiry">Whether to check if shares have expired (default: true).</param>
    /// <param name="encoding">The encoding to use (default: UTF-8).</param>
    /// <returns>The reconstructed secret string.</returns>
    public string ReconstructAuthenticatedSecretString(
        IReadOnlyList<AuthenticatedShare> authenticatedShares, 
        int t, 
        bool validateExpiry = true,
        Encoding? encoding = null)
    {
        encoding ??= Encoding.UTF8;
        var reconstructedBytes = ReconstructAuthenticatedSecret(authenticatedShares, t, validateExpiry);
        return encoding.GetString(reconstructedBytes);
    }

    /// <summary>
    /// Validates a collection of authenticated shares.
    /// </summary>
    /// <param name="authenticatedShares">The shares to validate.</param>
    /// <param name="checkExpiry">Whether to check for expired shares (default: true).</param>
    /// <returns>A list of validation results for each share.</returns>
    public IReadOnlyList<ShareValidationResult> ValidateShares(
        IReadOnlyList<AuthenticatedShare> authenticatedShares, 
        bool checkExpiry = true)
    {
        if (authenticatedShares == null)
            throw new ArgumentNullException(nameof(authenticatedShares));

        var results = new List<ShareValidationResult>();
        var currentTime = DateTimeOffset.UtcNow;

        foreach (var share in authenticatedShares)
        {
            if (share == null)
            {
                results.Add(new ShareValidationResult(null, false, "Share is null"));
                continue;
            }

            // Check expiry
            if (checkExpiry && share.IsExpiredAt(currentTime))
            {
                results.Add(new ShareValidationResult(share, false, "Share has expired"));
                continue;
            }

            // Verify signature
            bool signatureValid;
            try
            {
                signatureValid = _authenticator.VerifyShare(share);
            }
            catch (Exception ex)
            {
                results.Add(new ShareValidationResult(share, false, $"Signature verification failed: {ex.Message}"));
                continue;
            }

            if (!signatureValid)
            {
                results.Add(new ShareValidationResult(share, false, "Invalid signature - share may be tampered"));
                continue;
            }

            results.Add(new ShareValidationResult(share, true, null));
        }

        return results;
    }

    /// <summary>
    /// Represents the result of validating an authenticated share.
    /// </summary>
    public record ShareValidationResult
    {
        /// <summary>
        /// Gets the share that was validated.
        /// </summary>
        public AuthenticatedShare? Share { get; }

        /// <summary>
        /// Gets whether the share passed validation.
        /// </summary>
        public bool IsValid { get; }

        /// <summary>
        /// Gets the reason for validation failure, if any.
        /// </summary>
        public string? FailureReason { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ShareValidationResult"/> record.
        /// </summary>
        public ShareValidationResult(AuthenticatedShare? share, bool isValid, string? failureReason)
        {
            Share = share;
            IsValid = isValid;
            FailureReason = failureReason;
        }
    }
}