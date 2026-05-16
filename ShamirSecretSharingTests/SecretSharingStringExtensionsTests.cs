using ShamirSecretSharing;
using System.Text;

namespace ShamirSecretSharingTests;

[TestClass]
public class SecretSharingStringExtensionsTests
{
    [TestMethod]
    public void Splitter_SplitString_RoundTripsViaCombiner()
    {
        var splitter = new SecretSplitter();
        var combiner = new SecretCombiner();

        var shares = splitter.Split("hello", 3, 2);
        Assert.AreEqual(3, shares.Length);

        // Combine with 2 of the 3 shares
        var subset = new List<Share> { shares[0], shares[2] };
        var roundTripped = combiner.CombineString(subset);
        Assert.AreEqual("hello", roundTripped);
    }

    [TestMethod]
    public void CombineString_DefaultsToUtf8()
    {
        var splitter = new SecretSplitter();
        var combiner = new SecretCombiner();

        const string secret = "ünîcødé"; // non-ASCII to exercise UTF-8
        var shares = splitter.Split(secret, 3, 2); // splitter extension defaults to UTF-8 too

        var subset = new List<Share> { shares[0], shares[1] };
        var roundTripped = combiner.CombineString(subset);
        Assert.AreEqual(secret, roundTripped);

        // Sanity: byte-level round-trip uses UTF-8 by default
        var expectedBytes = Encoding.UTF8.GetBytes(secret);
        var bytes = combiner.Combine(subset);
        CollectionAssert.AreEqual(expectedBytes, bytes);
    }

    [TestMethod]
    public void CombineString_RespectsCustomEncoding()
    {
        var splitter = new SecretSplitter();
        var combiner = new SecretCombiner();

        const string secret = "round-trip";
        var shares = splitter.Split(secret, 3, 2, Encoding.Unicode);

        var subset = new List<Share> { shares[0], shares[1] };
        var roundTripped = combiner.CombineString(subset, Encoding.Unicode);
        Assert.AreEqual(secret, roundTripped);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentNullException))]
    public void SplitExtension_ThrowsOnNullReceiver()
    {
        ((SecretSplitter)null!).Split("hello", 3, 2);
    }
}
