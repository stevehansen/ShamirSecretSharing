using System.Security.Cryptography;
using System.Text;

namespace ShamirSecretSharing;

/// <summary>
/// Implements share authentication using HMAC-SHA256 for symmetric key-based integrity verification.
/// </summary>
/// <remarks>
/// This authenticator uses a shared secret key to generate and verify HMAC signatures.
/// All parties must possess the same key to authenticate shares.
/// </remarks>
public class HmacShareAuthenticator : IShareAuthenticator, IDisposable
{
    private readonly byte[] _key;
    private readonly HMACSHA256 _hmac;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="HmacShareAuthenticator"/> class.
    /// </summary>
    /// <param name="key">The shared secret key for HMAC operations.</param>
    /// <exception cref="ArgumentNullException">Thrown if the key is null.</exception>
    /// <exception cref="ArgumentException">Thrown if the key is empty or too short.</exception>
    public HmacShareAuthenticator(byte[] key)
    {
        if (key == null)
            throw new ArgumentNullException(nameof(key));
        if (key.Length == 0)
            throw new ArgumentException("Key cannot be empty.", nameof(key));
        if (key.Length < 16)
            throw new ArgumentException("Key should be at least 16 bytes for security.", nameof(key));

        _key = (byte[])key.Clone();
        _hmac = new HMACSHA256(_key);
    }

    /// <summary>
    /// Creates a new authenticator with a randomly generated key.
    /// </summary>
    /// <param name="keySize">The size of the key in bytes (default: 32).</param>
    /// <returns>A tuple containing the authenticator and the generated key.</returns>
    public static (HmacShareAuthenticator Authenticator, byte[] Key) CreateWithRandomKey(int keySize = 32)
    {
        if (keySize < 16)
            throw new ArgumentOutOfRangeException(nameof(keySize), "Key size should be at least 16 bytes.");

        var key = new byte[keySize];
        RandomNumberGenerator.Fill(key);
        return (new HmacShareAuthenticator(key), key);
    }

    /// <inheritdoc/>
    public string AlgorithmName => "HMAC-SHA256";

    /// <inheritdoc/>
    public byte[] SignShare(Share share, DateTimeOffset createdAt, DateTimeOffset? expiresAt = null)
    {
        if (share == null)
            throw new ArgumentNullException(nameof(share));

        var data = GetShareData(share, createdAt, expiresAt);
        
        lock (_hmac)
        {
            return _hmac.ComputeHash(data);
        }
    }

    /// <inheritdoc/>
    public bool VerifyShare(AuthenticatedShare authenticatedShare)
    {
        if (authenticatedShare == null)
            throw new ArgumentNullException(nameof(authenticatedShare));

        var data = GetShareData(
            authenticatedShare.Share,
            authenticatedShare.CreatedAt,
            authenticatedShare.ExpiresAt);

        byte[] computedSignature;
        lock (_hmac)
        {
            computedSignature = _hmac.ComputeHash(data);
        }

        return CryptographicOperations.FixedTimeEquals(computedSignature, authenticatedShare.Signature);
    }

    /// <summary>
    /// Generates the data to be signed from a share and its metadata.
    /// </summary>
    private static byte[] GetShareData(Share share, DateTimeOffset createdAt, DateTimeOffset? expiresAt)
    {
        var sb = new StringBuilder();
        
        // Include share data
        sb.Append(share.ToString());
        sb.Append('|');
        
        // Include creation timestamp
        sb.Append(createdAt.ToUnixTimeMilliseconds());
        
        // Include expiration if present
        if (expiresAt.HasValue)
        {
            sb.Append('|');
            sb.Append(expiresAt.Value.ToUnixTimeMilliseconds());
        }

        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    /// <summary>
    /// Disposes of the HMAC instance and clears the key from memory.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes of managed and unmanaged resources.
    /// </summary>
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _hmac?.Dispose();
                
                // Clear the key from memory
                if (_key != null)
                {
                    Array.Clear(_key, 0, _key.Length);
                }
            }
            _disposed = true;
        }
    }
}