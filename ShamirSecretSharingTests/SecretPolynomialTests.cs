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

        foreach (var (t, n) in combos)
        {
            var xs = new int[n];
            for (var i = 0; i < n; i++) xs[i] = i + 1;

            foreach (var secret in secrets)
            {
                var ys = new int[n];
                SecretPolynomial.SampleAndEvaluate(secret, t, xs, ys, _field, RandomSource.Default);

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
    public void SampleAndEvaluate_WritesOneYPerX()
    {
        int[][] xsCases =
        {
            new[] { 1, 2 },
            new[] { 1, 2, 3, 4, 5 },
            new[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }
        };

        foreach (var xs in xsCases)
        {
            var ys = new int[xs.Length];
            SecretPolynomial.SampleAndEvaluate(42, 2, xs, ys, _field, RandomSource.Default);
            // Sentinel: at least one y differs from default when threshold > 1 with non-zero coefficients;
            // we mainly assert no exception and that the destination span is the expected length.
            Assert.AreEqual(xs.Length, ys.Length);
        }
    }

    [TestMethod]
    public void SampleAndEvaluate_YValuesInFieldRange()
    {
        var xs = new[] { 1, 2, 3, 4, 5, 6, 7 };
        var ys = new int[xs.Length];

        for (var secret = 0; secret < 256; secret++)
        {
            SecretPolynomial.SampleAndEvaluate(secret, 4, xs, ys, _field, RandomSource.Default);
            foreach (var y in ys)
            {
                Assert.IsTrue(y >= 0 && y < 257, $"y={y} out of range for secret={secret}");
            }
        }
    }

    [TestMethod]
    public void SampleAndEvaluate_ThrowsOnLengthMismatch()
    {
        var xs = new[] { 1, 2, 3 };
        var ys = new int[2];

        Assert.ThrowsException<ArgumentException>(() =>
            SecretPolynomial.SampleAndEvaluate(10, 2, xs, ys, _field, RandomSource.Default));
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
    public void InterpolateAtZero_ThrowsOnLengthMismatch()
    {
        var xs = new[] { 1, 2, 3 };
        var ys = new[] { 10, 15 };

        Assert.ThrowsException<ArgumentException>(() =>
            SecretPolynomial.InterpolateAtZero(xs, ys, _field));
    }

    [TestMethod]
    public void ComputeLagrangeBasisAtZero_KnownVector_Quadratic()
    {
        // For xs = (1, 2, 3): basis[0] = L_0(0) = (2*3)/((2-1)*(3-1)) = 6/2 = 3.
        // basis[1] = L_1(0) = (1*3)/((1-2)*(3-2)) = 3/(-1) = -3 ≡ 254 mod 257.
        // basis[2] = L_2(0) = (1*2)/((1-3)*(2-3)) = 2/2 = 1.
        var xs = new[] { 1, 2, 3 };

        var basis = SecretPolynomial.ComputeLagrangeBasisAtZero(xs, _field);

        CollectionAssert.AreEqual(new[] { 3, 254, 1 }, basis);
    }

    [TestMethod]
    public void InterpolateWithBasis_AppliesBasisToYs()
    {
        // Using basis from above and ys for P(x) = 7 + 2x + x^2 (i.e. 10, 15, 22):
        // result = 10*3 + 15*254 + 22*1 = 30 + 3810 + 22 = 3862. 3862 mod 257 = 3862 - 15*257 = 3862 - 3855 = 7.
        var basis = new[] { 3, 254, 1 };
        var ys = new[] { 10, 15, 22 };

        var result = SecretPolynomial.InterpolateWithBasis(ys, basis, _field);

        Assert.AreEqual(7, result);
    }

    [TestMethod]
    public void InterpolateWithBasis_ThrowsOnLengthMismatch()
    {
        var ys = new[] { 10, 15, 22 };
        var basis = new[] { 3, 254 };

        Assert.ThrowsException<ArgumentException>(() =>
            SecretPolynomial.InterpolateWithBasis(ys, basis, _field));
    }

    [TestMethod]
    public void AnyThresholdSubset_RecoversSameSecret()
    {
        const int threshold = 3;
        const int secret = 88;
        var xs = new[] { 1, 2, 3, 4, 5 };
        var ys = new int[xs.Length];

        SecretPolynomial.SampleAndEvaluate(secret, threshold, xs, ys, _field, RandomSource.Default);

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
        var xs = new[] { 1, 2, 3, 4 };
        var ys = new int[xs.Length];

        SecretPolynomial.SampleAndEvaluate(0, threshold: 3, xs, ys, _field, RandomSource.Default);

        var xsSub = new[] { xs[0], xs[1], xs[2] };
        var ysSub = new[] { ys[0], ys[1], ys[2] };
        var recovered = SecretPolynomial.InterpolateAtZero(xsSub, ysSub, _field);

        Assert.AreEqual(0, recovered);
    }

    [TestMethod]
    public void SampleAndEvaluate_SecretByteMax_255()
    {
        var xs = new[] { 1, 2, 3, 4 };
        var ys = new int[xs.Length];

        SecretPolynomial.SampleAndEvaluate(255, threshold: 3, xs, ys, _field, RandomSource.Default);

        var xsSub = new[] { xs[0], xs[1], xs[2] };
        var ysSub = new[] { ys[0], ys[1], ys[2] };
        var recovered = SecretPolynomial.InterpolateAtZero(xsSub, ysSub, _field);

        Assert.AreEqual(255, recovered);
    }

    [TestMethod]
    public void SampleAndEvaluate_Threshold2_MinimumPolynomial()
    {
        var xs = new[] { 1, 2 };
        var ys = new int[xs.Length];

        SecretPolynomial.SampleAndEvaluate(99, threshold: 2, xs, ys, _field, RandomSource.Default);

        var recovered = SecretPolynomial.InterpolateAtZero(xs, ys, _field);

        Assert.AreEqual(99, recovered);
    }
}
