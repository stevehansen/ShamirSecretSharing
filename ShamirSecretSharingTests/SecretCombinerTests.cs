using ShamirSecretSharing;

namespace ShamirSecretSharingTests;

[TestClass]
public class SecretCombinerTests
{
    private readonly SecretSplitter _splitter = new();
    private readonly SecretCombiner _combiner = new();

    [TestMethod]
    public void Combine_RoundTrips_2of2()
    {
        byte[] secret = { 10, 20, 30 };
        var shares = _splitter.Split(secret, shareCount: 2, threshold: 2);

        var reconstructed = _combiner.Combine(shares);

        CollectionAssert.AreEqual(secret, reconstructed);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void ReconstructSecret_ThrowsWhenShareLengthsDiffer()
    {
        var s1 = new Share(1, new[] { 1, 2 });
        var s2 = new Share(2, new[] { 3 });
        _combiner.Combine(new List<Share> { s1, s2 });
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void Combine_ThrowsOnDuplicateXCoordinates()
    {
        var s1 = new Share(1, new[] { 1, 2 });
        var s2 = new Share(1, new[] { 3, 4 }); // same X
        _combiner.Combine(new List<Share> { s1, s2 });
    }

    [TestMethod]
    public void Combine_UsesAllSharesProvided_NoSilentTruncation()
    {
        byte[] secret = { 42, 7, 99, 1, 250 };
        var shares = _splitter.Split(secret, shareCount: 5, threshold: 3);

        // Pass all 5 shares to Combine — interpolation is over-determined but consistent
        var reconstructed = _combiner.Combine(shares);
        CollectionAssert.AreEqual(secret, reconstructed);

        // Pass only 2 of the 5 — combiner must NOT throw any "too few" exception;
        // it has no threshold knowledge. Result will be wrong, but the call must
        // return a byte array of the correct length.
        var tooFew = new List<Share> { shares[0], shares[1] };
        var underDetermined = _combiner.Combine(tooFew);
        Assert.IsNotNull(underDetermined);
        Assert.AreEqual(secret.Length, underDetermined.Length);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentNullException))]
    public void Combine_NullShares_Throws()
    {
        _combiner.Combine(null!);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void Combine_EmptyShares_Throws()
    {
        _combiner.Combine(new List<Share>());
    }

    [TestMethod]
    public void Combine_AcceptsExtraShares_RoundTripsCorrectly()
    {
        byte[] secret = { 1, 2, 3, 4, 5, 6, 7, 8 };
        var shares = _splitter.Split(secret, shareCount: 5, threshold: 3);

        // Combine all 5 shares (more than the polynomial degree requires).
        // Lagrange interpolation over more points than the polynomial degree
        // still recovers the constant term correctly.
        var reconstructed = _combiner.Combine(shares);
        CollectionAssert.AreEqual(secret, reconstructed);
    }

    [TestMethod]
    public void Combine_DoesNotSilentlyTruncate()
    {
        byte[] secret = { 11, 22, 33, 44 };
        var shares = _splitter.Split(secret, shareCount: 5, threshold: 3);

        // Combine with only 2 shares (below threshold). The combiner has no
        // threshold knowledge — it must NOT throw "insufficient shares".
        // The byte array returned will have the right length but wrong contents.
        var tooFew = new List<Share> { shares[0], shares[1] };
        var result = _combiner.Combine(tooFew);

        Assert.IsNotNull(result);
        Assert.AreEqual(secret.Length, result.Length);
    }
}
