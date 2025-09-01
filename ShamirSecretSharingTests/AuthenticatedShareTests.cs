using System.Text;
using ShamirSecretSharing;

namespace ShamirSecretSharingTests;

[TestClass]
public class AuthenticatedShareTests
{
    private HmacShareAuthenticator _authenticator = null!;
    private AuthenticatedShamirService _service = null!;
    private byte[] _testKey = null!;

    [TestInitialize]
    public void Setup()
    {
        _testKey = Encoding.UTF8.GetBytes("ThisIsATestKeyForHMACAuthentication123!");
        _authenticator = new HmacShareAuthenticator(_testKey);
        _service = new AuthenticatedShamirService(_authenticator);
    }

    [TestCleanup]
    public void Cleanup()
    {
        _authenticator?.Dispose();
    }

    [TestMethod]
    public void AuthenticatedShare_SerializationRoundTrip_Success()
    {
        // Arrange
        var share = new Share(1, [10, 20, 30]);
        var createdAt = DateTimeOffset.UtcNow;
        var expiresAt = createdAt.AddHours(1);
        var signature = _authenticator.SignShare(share, createdAt, expiresAt);
        var authShare = new AuthenticatedShare(share, signature, createdAt, expiresAt);

        // Act
        var serialized = authShare.ToString();
        var deserialized = AuthenticatedShare.Parse(serialized);

        // Assert
        Assert.AreEqual(authShare.Share.X, deserialized.Share.X);
        CollectionAssert.AreEqual(authShare.Share.YValues, deserialized.Share.YValues);
        CollectionAssert.AreEqual(authShare.Signature, deserialized.Signature);
        Assert.AreEqual(authShare.CreatedAt, deserialized.CreatedAt);
        Assert.AreEqual(authShare.ExpiresAt, deserialized.ExpiresAt);
    }

    [TestMethod]
    public void AuthenticatedShare_SerializationWithoutExpiry_Success()
    {
        // Arrange
        var share = new Share(5, [100, 200]);
        var createdAt = DateTimeOffset.UtcNow;
        var signature = _authenticator.SignShare(share, createdAt, null);
        var authShare = new AuthenticatedShare(share, signature, createdAt, null);

        // Act
        var serialized = authShare.ToString();
        var deserialized = AuthenticatedShare.Parse(serialized);

        // Assert
        Assert.AreEqual(authShare.Share.X, deserialized.Share.X);
        Assert.IsNull(deserialized.ExpiresAt);
    }

    [TestMethod]
    public void AuthenticatedShare_IsExpired_CorrectlyIdentifiesExpiredShares()
    {
        // Arrange
        var share = new Share(1, [10]);
        var createdAt = DateTimeOffset.UtcNow.AddHours(-2);
        var expiresAt = DateTimeOffset.UtcNow.AddHours(-1); // Expired 1 hour ago
        var signature = _authenticator.SignShare(share, createdAt, expiresAt);
        var expiredShare = new AuthenticatedShare(share, signature, createdAt, expiresAt);

        var futureExpiry = DateTimeOffset.UtcNow.AddHours(1);
        var validShare = new AuthenticatedShare(share, signature, createdAt, futureExpiry);

        // Act & Assert
        Assert.IsTrue(expiredShare.IsExpired());
        Assert.IsFalse(validShare.IsExpired());
    }

    [TestMethod]
    public void HmacShareAuthenticator_SignAndVerify_Success()
    {
        // Arrange
        var share = new Share(1, [10, 20, 30]);
        var createdAt = DateTimeOffset.UtcNow;
        var expiresAt = createdAt.AddHours(1);

        // Act
        var signature = _authenticator.SignShare(share, createdAt, expiresAt);
        var authShare = new AuthenticatedShare(share, signature, createdAt, expiresAt);
        var isValid = _authenticator.VerifyShare(authShare);

        // Assert
        Assert.IsTrue(isValid);
    }

    [TestMethod]
    public void HmacShareAuthenticator_VerifyTamperedShare_Fails()
    {
        // Arrange
        var share = new Share(1, [10, 20, 30]);
        var createdAt = DateTimeOffset.UtcNow;
        var signature = _authenticator.SignShare(share, createdAt, null);
        
        // Tamper with the share
        var tamperedShare = new Share(1, [10, 20, 31]); // Changed last value
        var authShare = new AuthenticatedShare(tamperedShare, signature, createdAt, null);

        // Act
        var isValid = _authenticator.VerifyShare(authShare);

        // Assert
        Assert.IsFalse(isValid);
    }

    [TestMethod]
    public void HmacShareAuthenticator_VerifyWithWrongKey_Fails()
    {
        // Arrange
        var share = new Share(1, [10, 20, 30]);
        var createdAt = DateTimeOffset.UtcNow;
        var signature = _authenticator.SignShare(share, createdAt, null);
        var authShare = new AuthenticatedShare(share, signature, createdAt, null);

        // Create authenticator with different key
        var wrongKey = Encoding.UTF8.GetBytes("ThisIsADifferentKeyThatShouldNotWork!");
        using var wrongAuthenticator = new HmacShareAuthenticator(wrongKey);

        // Act
        var isValid = wrongAuthenticator.VerifyShare(authShare);

        // Assert
        Assert.IsFalse(isValid);
    }

    [TestMethod]
    public void AuthenticatedShamirService_SplitAndReconstruct_Success()
    {
        // Arrange
        var secret = "This is a secret message!";
        var n = 5;
        var t = 3;

        // Act
        var shares = _service.SplitAuthenticatedSecret(secret, n, t);
        var reconstructed = _service.ReconstructAuthenticatedSecretString(shares.Take(t).ToList(), t);

        // Assert
        Assert.AreEqual(secret, reconstructed);
        Assert.AreEqual(n, shares.Length);
    }

    [TestMethod]
    public void AuthenticatedShamirService_ReconstructWithTamperedShare_Fails()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Secret data");
        var n = 5;
        var t = 3;
        var shares = _service.SplitAuthenticatedSecret(secret, n, t);

        // Tamper with one share
        var tamperedShare = shares[0];
        var modifiedShareData = new Share(tamperedShare.Share.X, [255, 255, 255]); // Completely wrong values
        shares[0] = new AuthenticatedShare(
            modifiedShareData,
            tamperedShare.Signature,
            tamperedShare.CreatedAt,
            tamperedShare.ExpiresAt);

        // Act & Assert
        var ex = Assert.ThrowsException<InvalidOperationException>(() =>
            _service.ReconstructAuthenticatedSecret(shares.Take(t).ToList(), t));
        
        Assert.IsTrue(ex.Message.Contains("Invalid signature"));
    }

    [TestMethod]
    public void AuthenticatedShamirService_ReconstructWithExpiredShare_Fails()
    {
        // Arrange
        var secret = "Test secret";
        var n = 5;
        var t = 3;
        var expiresIn = TimeSpan.FromMilliseconds(-1000); // Already expired
        var shares = _service.SplitAuthenticatedSecret(secret, n, t, expiresIn);

        // Act & Assert
        var ex = Assert.ThrowsException<InvalidOperationException>(() =>
            _service.ReconstructAuthenticatedSecretString(shares.Take(t).ToList(), t));
        
        Assert.IsTrue(ex.Message.Contains("expired"));
    }

    [TestMethod]
    public void AuthenticatedShamirService_ReconstructWithExpiredShareButValidationDisabled_Success()
    {
        // Arrange
        var secret = "Test secret";
        var n = 5;
        var t = 3;
        var expiresIn = TimeSpan.FromMilliseconds(-1000); // Already expired
        var shares = _service.SplitAuthenticatedSecret(secret, n, t, expiresIn);

        // Act
        var reconstructed = _service.ReconstructAuthenticatedSecretString(
            shares.Take(t).ToList(), t, validateExpiry: false);

        // Assert
        Assert.AreEqual(secret, reconstructed);
    }

    [TestMethod]
    public void AuthenticatedShamirService_ValidateShares_IdentifiesAllIssues()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Test");
        var shares = _service.SplitAuthenticatedSecret(secret, 5, 3, TimeSpan.FromHours(1));
        
        // Create various problematic shares
        var sharesList = new List<AuthenticatedShare>
        {
            shares[0], // Valid share
            null!, // Null share
            new AuthenticatedShare( // Expired share
                shares[1].Share,
                shares[1].Signature,
                DateTimeOffset.UtcNow.AddHours(-2),
                DateTimeOffset.UtcNow.AddHours(-1)),
            new AuthenticatedShare( // Tampered share
                new Share(shares[2].Share.X, [255, 255]),
                shares[2].Signature,
                shares[2].CreatedAt,
                shares[2].ExpiresAt)
        };

        // Act
        var results = _service.ValidateShares(sharesList);

        // Assert
        Assert.AreEqual(4, results.Count);
        Assert.IsTrue(results[0].IsValid); // First share is valid
        Assert.IsFalse(results[1].IsValid); // Null share
        Assert.IsTrue(results[1].FailureReason!.Contains("null"));
        Assert.IsFalse(results[2].IsValid); // Expired share
        Assert.IsTrue(results[2].FailureReason!.Contains("expired"));
        Assert.IsFalse(results[3].IsValid); // Tampered share
        Assert.IsTrue(results[3].FailureReason!.Contains("signature"));
    }

    [TestMethod]
    public void AuthenticatedShamirService_ReconstructWithExtraValidShares_Success()
    {
        // Arrange
        var secret = "Secret with extra shares";
        var n = 7;
        var t = 3;
        var shares = _service.SplitAuthenticatedSecret(secret, n, t);

        // Act - provide more shares than needed
        var reconstructed = _service.ReconstructAuthenticatedSecretString(shares.ToList(), t);

        // Assert
        Assert.AreEqual(secret, reconstructed);
    }

    [TestMethod]
    public void HmacShareAuthenticator_CreateWithRandomKey_Success()
    {
        // Act
        var (authenticator, key) = HmacShareAuthenticator.CreateWithRandomKey();
        
        using (authenticator)
        {
            // Arrange
            var share = new Share(1, [10, 20]);
            var createdAt = DateTimeOffset.UtcNow;
            
            // Act
            var signature = authenticator.SignShare(share, createdAt, null);
            var authShare = new AuthenticatedShare(share, signature, createdAt, null);
            var isValid = authenticator.VerifyShare(authShare);

            // Assert
            Assert.IsNotNull(key);
            Assert.AreEqual(32, key.Length); // Default key size
            Assert.IsTrue(isValid);
        }
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void HmacShareAuthenticator_EmptyKey_ThrowsException()
    {
        // Act
        _ = new HmacShareAuthenticator([]);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void HmacShareAuthenticator_ShortKey_ThrowsException()
    {
        // Act
        _ = new HmacShareAuthenticator(new byte[10]); // Less than 16 bytes
    }

    [TestMethod]
    public void AuthenticatedShare_ParseInvalidFormat_ThrowsException()
    {
        // Arrange
        var invalidStrings = new[]
        {
            "",
            "InvalidFormat",
            "1:FF|NoSignature",
            "1:FF|InvalidBase64!@#|2024-01-01T00:00:00Z"
        };

        // Act & Assert
        foreach (var invalid in invalidStrings)
        {
            Assert.ThrowsException<ArgumentException>(() => AuthenticatedShare.Parse(invalid));
        }
    }
}