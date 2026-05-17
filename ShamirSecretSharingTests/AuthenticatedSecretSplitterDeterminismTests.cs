using ShamirSecretSharing;

namespace ShamirSecretSharingTests;

[TestClass]
public class AuthenticatedSecretSplitterDeterminismTests
{
    /// <summary>
    /// Builds a script of <paramref name="length"/> bytes whose 4-byte LE
    /// windows always mask to a value &lt; 257, i.e. always accepted by the
    /// prime-257 rejection sampler. This keeps the script-byte → field-element
    /// mapping predictable so the splitter cannot exhaust the script via
    /// rejection.
    /// </summary>
    private static byte[] BuildSafeScript(int length)
    {
        var script = new byte[length];
        for (var i = 0; i < length; i++)
            script[i] = (i % 4) == 1 ? (byte)0x00 : (byte)(i & 0xFF);
        return script;
    }

    [TestMethod]
    public void Split_IsDeterministic_UnderFixedScript()
    {
        // 32-byte issue key + secret-share coefficients + key-share coefficients.
        // Generous buffer: 1024 bytes covers everything for the (3,5) below.
        var script = BuildSafeScript(1024);
        byte[] secret = { 0x11, 0x22, 0x33, 0x44 };

        var a = new AuthenticatedSecretSplitter(prime: 257, new SequenceRandomSource(script))
            .Split(secret, shareCount: 5, threshold: 3);
        var b = new AuthenticatedSecretSplitter(prime: 257, new SequenceRandomSource(script))
            .Split(secret, shareCount: 5, threshold: 3);

        Assert.AreEqual(a.Length, b.Length);
        for (var i = 0; i < a.Length; i++)
        {
            Assert.AreEqual(a[i].ToString(), b[i].ToString(),
                $"Share {i} differs between runs — single-stream RandomSource is not threaded through deterministically.");
        }
    }

    [TestMethod]
    public void Split_DeterministicShares_RoundTripThroughCombiner()
    {
        // Proves the seam didn't break the actual scheme: deterministic shares
        // must still reconstruct via the real combiner.
        var script = BuildSafeScript(1024);
        byte[] secret = { 0x42, 0xAB, 0xCD };

        var shares = new AuthenticatedSecretSplitter(prime: 257, new SequenceRandomSource(script))
            .Split(secret, shareCount: 5, threshold: 3);

        var combiner = new AuthenticatedSecretCombiner();
        var reconstructed = combiner.Combine(new[] { shares[0], shares[2], shares[4] });

        CollectionAssert.AreEqual(secret, reconstructed);
    }
}
