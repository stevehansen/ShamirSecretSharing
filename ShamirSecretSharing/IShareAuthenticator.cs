namespace ShamirSecretSharing;

/// <summary>
/// Defines the contract for implementing share authentication strategies.
/// </summary>
/// <remarks>
/// Implementations can use various cryptographic approaches such as HMAC, RSA, or ECDSA
/// to provide integrity and authenticity verification for shares.
/// </remarks>
public interface IShareAuthenticator
{
    /// <summary>
    /// Generates a cryptographic signature for a share.
    /// </summary>
    /// <param name="share">The share to sign.</param>
    /// <param name="createdAt">The timestamp when the share was created.</param>
    /// <param name="expiresAt">The optional expiration timestamp.</param>
    /// <returns>The cryptographic signature as a byte array.</returns>
    byte[] SignShare(Share share, DateTimeOffset createdAt, DateTimeOffset? expiresAt = null);

    /// <summary>
    /// Verifies the cryptographic signature of an authenticated share.
    /// </summary>
    /// <param name="authenticatedShare">The authenticated share to verify.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    bool VerifyShare(AuthenticatedShare authenticatedShare);

    /// <summary>
    /// Gets the algorithm name used for authentication.
    /// </summary>
    string AlgorithmName { get; }
}