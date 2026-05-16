using System.Security.Cryptography;
using ShamirSecretSharing;

namespace ShamirSecretSharingTests;

[TestClass]
public class SecretPolynomialTests
{
    private readonly FiniteField _field = new(257);

    [TestMethod]
    public void SampleAndEvaluate_RoundTrip_RecoversSecretByte()
    {
        (int t, int n)[] combos = { (2, 3), (3, 5), (5, 7) };
        int[] secrets = { 0, 1, 77, 254, 255 };
        using var rng = RandomNumberGenerator.Create();

        foreach (var (t, n) in combos)
        {
            var xs = new int[n];
            for (var i = 0; i < n; i++) xs[i] = i + 1;

            foreach (var secret in secrets)
            {
                var ys = SecretPolynomial.SampleAndEvaluate(secret, t, xs, _field, rng);

                var xsSubset = new int[t];
                var ysSubset = new int[t];
                Array.Copy(xs, xsSubset, t);
                Array.Copy(ys, ysSubset, t);

                var recovered = SecretPolynomial.InterpolateAtZero(xsSubset, ysSubset, _field);
                Assert.AreEqual(secret, recovered, $"Failed for (t={t}, n={n}, secret={secret})");
            }
        }
    }

    [TestMethod]
    public void SampleAndEvaluate_ReturnsOneYPerX()
    {
        using var rng = RandomNumberGenerator.Create();
        int[][] xsCases =
        {
            new[] { 1, 2 },
            new[] { 1, 2, 3, 4, 5 },
            new[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }
        };

        foreach (var xs in xsCases)
        {
            var ys = SecretPolynomial.SampleAndEvaluate(42, 2, xs, _field, rng);
            Assert.AreEqual(xs.Length, ys.Length);
        }
    }

    [TestMethod]
    public void SampleAndEvaluate_YValuesInFieldRange()
    {
        using var rng = RandomNumberGenerator.Create();
        var xs = new[] { 1, 2, 3, 4, 5, 6, 7 };

        for (var secret = 0; secret < 256; secret++)
        {
            var ys = SecretPolynomial.SampleAndEvaluate(secret, 4, xs, _field, rng);
            foreach (var y in ys)
            {
                Assert.IsTrue(y >= 0 && y < 257, $"y={y} out of range for secret={secret}");
            }
        }
    }

    [TestMethod]
    public void SampleAndEvaluate_Deterministic_WithScriptedRng()
    {
        var xs = new[] { 1, 2, 3, 4, 5 };
        const int threshold = 4;
        const int secret = 123;
        byte[] script = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

        var rng1 = new ScriptedRng(script);
        var rng2 = new ScriptedRng(script);

        var ys1 = SecretPolynomial.SampleAndEvaluate(secret, threshold, xs, _field, rng1);
        var ys2 = SecretPolynomial.SampleAndEvaluate(secret, threshold, xs, _field, rng2);

        CollectionAssert.AreEqual(ys1, ys2);
    }

    [TestMethod]
    public void SampleAndEvaluate_KnownPolynomial_FixedCoefficients()
    {
        // All random bytes = 0x03 → coefficients = (10, 3, 3).
        // P(x) = 10 + 3x + 3x^2 mod 257
        // P(1) = 16, P(2) = 28, P(3) = 46
        var rng = new ScriptedRng(0x03, length: 2);
        var xs = new[] { 1, 2, 3 };

        var ys = SecretPolynomial.SampleAndEvaluate(10, threshold: 3, xs, _field, rng);

        CollectionAssert.AreEqual(new[] { 16, 28, 46 }, ys);
    }

    [TestMethod]
    public void InterpolateAtZero_KnownVector_Linear()
    {
        // Points (1, 5) and (2, 8). Line: y = 3x + 2. At x=0, y = 2.
        var xs = new[] { 1, 2 };
        var ys = new[] { 5, 8 };

        var result = SecretPolynomial.InterpolateAtZero(xs, ys, _field);

        Assert.AreEqual(2, result);
    }

    [TestMethod]
    public void InterpolateAtZero_KnownVector_Quadratic()
    {
        // P(x) = 7 + 2x + x^2; P(1)=10, P(2)=15, P(3)=22. At x=0, y=7.
        var xs = new[] { 1, 2, 3 };
        var ys = new[] { 10, 15, 22 };

        var result = SecretPolynomial.InterpolateAtZero(xs, ys, _field);

        Assert.AreEqual(7, result);
    }

    [TestMethod]
    public void InterpolateAtZero_AnyThresholdSubset_RecoversSame()
    {
        const int threshold = 3;
        const int secret = 88;
        var xs = new[] { 1, 2, 3, 4, 5 };
        var rng = new ScriptedRng(0x07, length: 2);

        var ys = SecretPolynomial.SampleAndEvaluate(secret, threshold, xs, _field, rng);

        (int, int, int)[] subsets =
        {
            (0, 1, 2),
            (0, 2, 4),
            (1, 3, 4),
            (2, 3, 4),
            (0, 1, 4)
        };

        foreach (var (a, b, c) in subsets)
        {
            var xsSub = new[] { xs[a], xs[b], xs[c] };
            var ysSub = new[] { ys[a], ys[b], ys[c] };
            var recovered = SecretPolynomial.InterpolateAtZero(xsSub, ysSub, _field);
            Assert.AreEqual(secret, recovered, $"Subset ({a},{b},{c}) failed");
        }
    }

    [TestMethod]
    public void SampleAndEvaluate_SecretByteZero()
    {
        using var rng = RandomNumberGenerator.Create();
        var xs = new[] { 1, 2, 3, 4 };

        var ys = SecretPolynomial.SampleAndEvaluate(0, threshold: 3, xs, _field, rng);

        var xsSub = new[] { xs[0], xs[1], xs[2] };
        var ysSub = new[] { ys[0], ys[1], ys[2] };
        var recovered = SecretPolynomial.InterpolateAtZero(xsSub, ysSub, _field);

        Assert.AreEqual(0, recovered);
    }

    [TestMethod]
    public void SampleAndEvaluate_SecretByteMax_255()
    {
        using var rng = RandomNumberGenerator.Create();
        var xs = new[] { 1, 2, 3, 4 };

        var ys = SecretPolynomial.SampleAndEvaluate(255, threshold: 3, xs, _field, rng);

        var xsSub = new[] { xs[0], xs[1], xs[2] };
        var ysSub = new[] { ys[0], ys[1], ys[2] };
        var recovered = SecretPolynomial.InterpolateAtZero(xsSub, ysSub, _field);

        Assert.AreEqual(255, recovered);
    }

    [TestMethod]
    public void SampleAndEvaluate_Threshold2_MinimumPolynomial()
    {
        using var rng = RandomNumberGenerator.Create();
        var xs = new[] { 1, 2 };

        var ys = SecretPolynomial.SampleAndEvaluate(99, threshold: 2, xs, _field, rng);

        var recovered = SecretPolynomial.InterpolateAtZero(xs, ys, _field);

        Assert.AreEqual(99, recovered);
    }
}

// Test-only RNG. Overrides GetBytes(byte[]) and GetBytes(Span<byte>); if SecretPolynomial
// ever switches to GetNonZeroBytes or the static RandomNumberGenerator.Fill, add an override here.
internal sealed class ScriptedRng : RandomNumberGenerator
{
    private readonly byte[] _script;
    private int _pos;

    public ScriptedRng(params byte[] script) { _script = script; }

    public ScriptedRng(byte fillValue, int length)
    {
        _script = new byte[length];
        Array.Fill(_script, fillValue);
    }

    public override void GetBytes(byte[] data) => GetBytes(data.AsSpan());

    public override void GetBytes(Span<byte> data)
    {
        for (var i = 0; i < data.Length; i++)
        {
            if (_pos >= _script.Length)
                throw new InvalidOperationException("ScriptedRng exhausted.");
            data[i] = _script[_pos++];
        }
    }
}
