using ShamirSecretSharing;

namespace ShamirSecretSharingTests;

[TestClass]
public class RandomSourceTests
{
    [TestMethod]
    public void Default_ReturnsCryptoRandomSourceSingleton()
    {
        Assert.AreSame(CryptoRandomSource.Instance, RandomSource.Default);
    }

    [TestMethod]
    public void GetInts_ExclusiveUpperBound_Zero_Throws()
    {
        var src = new SequenceRandomSource(new byte[16]);
        var dest = new int[1];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => src.GetInts(dest, 0));
    }

    [TestMethod]
    public void GetInts_ExclusiveUpperBound_Negative_Throws()
    {
        var src = new SequenceRandomSource(new byte[16]);
        var dest = new int[1];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => src.GetInts(dest, -1));
    }

    [TestMethod]
    public void GetInts_RejectionSampling_SkipsOutOfRangeWindow()
    {
        // Prime 257: RoundUpToPowerOf2 = 512, mask = 511.
        // First 4-byte window 0xFF 0x01 0x00 0x00 → 0x000001FF (511) & 511 = 511 → rejected.
        // Second window 0x05 0x00 0x00 0x00 → 5 & 511 = 5 → accepted.
        byte[] script = { 0xFF, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00 };
        var src = new SequenceRandomSource(script);
        var dest = new int[1];

        src.GetInts(dest, exclusiveUpperBound: 257);

        Assert.AreEqual(5, dest[0]);
    }

    [DataTestMethod]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(257)]
    [DataRow(65537)]
    [DataRow(int.MaxValue)]
    public void GetInts_BoundaryPrime_AllOutputsInRange(int exclusiveUpperBound)
    {
        // Worst-case rejection rate is < 50% (mask covers at most 2x the bound),
        // so 16 ints * 4 bytes * 2 rejection slack ~ 128 bytes; 4096 is generous.
        var script = new byte[4096];
        new Random(12345).NextBytes(script);
        var src = new SequenceRandomSource(script);
        var dest = new int[16];

        src.GetInts(dest, exclusiveUpperBound);

        foreach (var v in dest)
        {
            Assert.IsTrue(v >= 0, $"v={v} negative for bound={exclusiveUpperBound}");
            Assert.IsTrue(v < exclusiveUpperBound, $"v={v} >= bound={exclusiveUpperBound}");
        }
    }

    [TestMethod]
    public void GetInts_ProducesDeterministicSequence_FromKnownScript()
    {
        // Three 4-byte windows, each in-range for prime 257.
        // Window 1: 0x01 0x00 0x00 0x00 → 1 & 511 = 1.
        // Window 2: 0x42 0x00 0x00 0x00 → 0x42 & 511 = 66.
        // Window 3: 0x05 0x01 0x00 0x00 → 0x00000105 (261) & 511 = 261 → reject.
        //   Next: 0x07 0x00 0x00 0x00 → 7.
        byte[] script = { 0x01, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00 };
        var src = new SequenceRandomSource(script);
        var dest = new int[3];

        src.GetInts(dest, exclusiveUpperBound: 257);

        CollectionAssert.AreEqual(new[] { 1, 66, 7 }, dest);
    }
}

[TestClass]
public class SequenceRandomSourceTests
{
    [TestMethod]
    public void GetBytes_ReplaysScriptExactly()
    {
        byte[] script = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };
        var src = new SequenceRandomSource(script);

        var first = new byte[3];
        src.GetBytes(first);
        var second = new byte[5];
        src.GetBytes(second);

        CollectionAssert.AreEqual(new byte[] { 0xDE, 0xAD, 0xBE }, first);
        CollectionAssert.AreEqual(new byte[] { 0xEF, 0x01, 0x02, 0x03, 0x04 }, second);
    }

    [TestMethod]
    public void GetBytes_Exhaustion_ThrowsInvalidOperation()
    {
        byte[] script = { 0x01, 0x02, 0x03, 0x04 };
        var src = new SequenceRandomSource(script);

        src.GetBytes(new byte[4]); // consume entire script

        var ex = Assert.ThrowsException<InvalidOperationException>(() => src.GetBytes(new byte[1]));
        StringAssert.Contains(ex.Message, "exhausted");
    }

    [TestMethod]
    public void GetBytes_OverlongFirstRequest_ThrowsInvalidOperation()
    {
        byte[] script = { 0x01, 0x02, 0x03, 0x04 };
        var src = new SequenceRandomSource(script);

        Assert.ThrowsException<InvalidOperationException>(() => src.GetBytes(new byte[8]));
    }

    [TestMethod]
    public void ScriptIsCopied_MutationOfSourceDoesNotAffectPlayback()
    {
        byte[] script = { 0x01, 0x02, 0x03, 0x04 };
        var src = new SequenceRandomSource(script);

        script[0] = 0xFF;

        var dest = new byte[1];
        src.GetBytes(dest);
        Assert.AreEqual(0x01, dest[0]);
    }
}
