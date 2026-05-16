using ShamirSecretSharing;

namespace ShamirSecretSharingTests;

[TestClass]
public class SecretSplitterTests
{
    [TestMethod]
    [ExpectedException(typeof(ArgumentOutOfRangeException))]
    public void Split_N_TooLargeForPrime()
    {
        var splitter = new SecretSplitter(prime: 5); // Small prime
        byte[] secret = { 1, 2 };
        splitter.Split(secret, shareCount: 5, threshold: 2); // shareCount must be < prime
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void Split_SecretByteTooLargeForPrime()
    {
        var splitter = new SecretSplitter(prime: 17); // Small prime
        byte[] secret = { 10, 20 }; // 20 is > 17
        splitter.Split(secret, shareCount: 3, threshold: 2);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentOutOfRangeException))]
    public void Split_ThrowsWhenThresholdTooSmall()
    {
        var splitter = new SecretSplitter();
        byte[] secret = { 1, 2, 3 };
        splitter.Split(secret, shareCount: 3, threshold: 1);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentOutOfRangeException))]
    public void Split_ThrowsWhenNLessThanT()
    {
        var splitter = new SecretSplitter();
        byte[] secret = { 1, 2, 3 };
        splitter.Split(secret, shareCount: 2, threshold: 3);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void Split_ThrowsWhenSecretEmpty()
    {
        var splitter = new SecretSplitter();
        splitter.Split(Array.Empty<byte>(), shareCount: 2, threshold: 2);
    }
}
