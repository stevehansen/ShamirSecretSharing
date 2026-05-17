using ShamirSecretSharing;

namespace ShamirSecretSharingTests;

[TestClass]
public class SecretSplitterDeterminismTests
{
    [TestMethod]
    public void GoldenProbe_Single_Byte()
    {
        // Script: 3 in-range coefficient bytes (each 4-byte LE window < 257).
        byte[] script = { 0x05, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00 };
        var splitter = new SecretSplitter(prime: 257, randomSource: new SequenceRandomSource(script));

        var shares = splitter.Split(new byte[] { 0x42 }, shareCount: 3, threshold: 2);

        // threshold=2 → 1 random coefficient per byte → consumes 4 script bytes per secret byte.
        // Polynomial: P(x) = 0x42 + 0x05*x.
        // P(1) = 0x47 = 71, P(2) = 0x4C = 76, P(3) = 0x51 = 81.
        Assert.AreEqual(3, shares.Length);
        Assert.AreEqual("01:47", shares[0].ToString());
        Assert.AreEqual("02:4C", shares[1].ToString());
        Assert.AreEqual("03:51", shares[2].ToString());
    }

    [TestMethod]
    public void GoldenProbe_MultiByte_Threshold3()
    {
        // 2 secret bytes × (threshold-1=2) coefficients × 4 bytes per int = 16 bytes of script needed.
        byte[] script =
        {
            0x05, 0x00, 0x00, 0x00, // first byte coeff_1 = 5
            0x07, 0x00, 0x00, 0x00, // first byte coeff_2 = 7
            0x03, 0x00, 0x00, 0x00, // second byte coeff_1 = 3
            0x02, 0x00, 0x00, 0x00, // second byte coeff_2 = 2
        };
        var splitter = new SecretSplitter(prime: 257, randomSource: new SequenceRandomSource(script));

        var shares = splitter.Split(new byte[] { 0x10, 0x20 }, shareCount: 3, threshold: 3);

        // P0(x) = 16 + 5x + 7x^2. P0(1)=28, P0(2)=54, P0(3)=94.
        // P1(x) = 32 + 3x + 2x^2. P1(1)=37, P1(2)=46, P1(3)=59.
        Assert.AreEqual("01:1C25", shares[0].ToString());
        Assert.AreEqual("02:362E", shares[1].ToString());
        Assert.AreEqual("03:5E3B", shares[2].ToString());
    }

    [TestMethod]
    public void IdenticalScripts_ProduceIdenticalShares()
    {
        byte[] script =
        {
            0x12, 0x00, 0x00, 0x00,
            0x34, 0x00, 0x00, 0x00,
            0x56, 0x00, 0x00, 0x00,
            0x78, 0x00, 0x00, 0x00,
        };

        var a = new SecretSplitter(prime: 257, randomSource: new SequenceRandomSource(script))
            .Split(new byte[] { 0x11, 0x22 }, shareCount: 2, threshold: 2);
        var b = new SecretSplitter(prime: 257, randomSource: new SequenceRandomSource(script))
            .Split(new byte[] { 0x11, 0x22 }, shareCount: 2, threshold: 2);

        Assert.AreEqual(a.Length, b.Length);
        for (var i = 0; i < a.Length; i++)
        {
            Assert.AreEqual(a[i].X, b[i].X);
            CollectionAssert.AreEqual(a[i].YValues, b[i].YValues);
        }
    }

    [TestMethod]
    public void DefaultCtor_Parity_WithExplicitCryptoSource_BothRoundTrip()
    {
        // Can't compare shares byte-for-byte (random), but both must reconstruct.
        byte[] secret = { 1, 2, 3, 4, 5, 200, 255 };

        var defaultShares = new SecretSplitter()
            .Split(secret, shareCount: 5, threshold: 3);
        var explicitShares = new SecretSplitter(prime: 257, CryptoRandomSource.Instance)
            .Split(secret, shareCount: 5, threshold: 3);

        var combiner = new SecretCombiner();
        CollectionAssert.AreEqual(secret, combiner.Combine(new[] { defaultShares[0], defaultShares[2], defaultShares[4] }));
        CollectionAssert.AreEqual(secret, combiner.Combine(new[] { explicitShares[0], explicitShares[2], explicitShares[4] }));
    }
}
