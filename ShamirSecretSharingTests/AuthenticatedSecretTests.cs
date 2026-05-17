using ShamirSecretSharing;

namespace ShamirSecretSharingTests;

[TestClass]
public class AuthenticatedSecretTests
{
    private readonly AuthenticatedSecretSplitter _splitter = new();
    private readonly AuthenticatedSecretCombiner _combiner = new();

    [TestMethod]
    public void Split_RoundTrips_DefaultPrime_2of2()
    {
        byte[] secret = { 10, 20, 30 };
        var shares = _splitter.Split(secret, shareCount: 2, threshold: 2);

        var reconstructed = _combiner.Combine(shares);

        CollectionAssert.AreEqual(secret, reconstructed);
    }

    [TestMethod]
    public void Split_RoundTrips_DefaultPrime_5of5()
    {
        byte[] secret = { 1, 2, 3, 4, 5, 6, 7, 8 };
        var shares = _splitter.Split(secret, shareCount: 5, threshold: 5);

        var reconstructed = _combiner.Combine(shares);

        CollectionAssert.AreEqual(secret, reconstructed);
    }

    [TestMethod]
    public void Split_RoundTrips_DefaultPrime_3of5()
    {
        byte[] secret = { 42, 7, 99, 1, 250 };
        var shares = _splitter.Split(secret, shareCount: 5, threshold: 3);

        var subset = new List<AuthenticatedShare> { shares[0], shares[1], shares[2] };
        var reconstructed = _combiner.Combine(subset);

        CollectionAssert.AreEqual(secret, reconstructed);
    }

    [TestMethod]
    public void Split_RoundTrips_DefaultPrime_3of10()
    {
        byte[] secret = { 100, 101, 102, 103 };
        var shares = _splitter.Split(secret, shareCount: 10, threshold: 3);

        var subset = new List<AuthenticatedShare> { shares[0], shares[4], shares[9] };
        var reconstructed = _combiner.Combine(subset);

        CollectionAssert.AreEqual(secret, reconstructed);
    }

    [TestMethod]
    public void Splitter_Ctor_RejectsPrimeBelow256()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => new AuthenticatedSecretSplitter(prime: 23));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => new AuthenticatedSecretSplitter(prime: 255));
    }

    [TestMethod]
    public void Combiner_Ctor_RejectsPrimeBelow256()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => new AuthenticatedSecretCombiner(prime: 23));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => new AuthenticatedSecretCombiner(prime: 255));
    }

    [TestMethod]
    public void Combine_EveryThreeOfFiveSubset_Reconstructs()
    {
        byte[] secret = { 1, 7, 42, 200, 255, 0, 13 };
        var shares = _splitter.Split(secret, shareCount: 5, threshold: 3);

        var subsetCount = 0;
        for (var i = 0; i < 5; i++)
        for (var j = i + 1; j < 5; j++)
        for (var k = j + 1; k < 5; k++)
        {
            var subset = new List<AuthenticatedShare> { shares[i], shares[j], shares[k] };
            var reconstructed = _combiner.Combine(subset);
            CollectionAssert.AreEqual(secret, reconstructed,
                $"Subset ({i},{j},{k}) failed to reconstruct.");
            subsetCount++;
        }
        Assert.AreEqual(10, subsetCount, "Should have enumerated 10 subsets of 3-of-5.");
    }

    [TestMethod]
    public void Combine_TamperedY_Throws()
    {
        byte[] secret = { 10, 20, 30, 40 };
        var shares = _splitter.Split(secret, shareCount: 5, threshold: 3);

        // Tamper share 0's first Y-value (+1 mod prime).
        var bad = TamperShareY(shares[0], yIndex: 0, prime: 257);
        var subset = new List<AuthenticatedShare> { bad, shares[1], shares[2] };

        var ex = Assert.ThrowsException<ShareAuthenticationException>(() => _combiner.Combine(subset));
        CollectionAssert.Contains(ex.OffendingShareXs.ToArray(), bad.Share.X);
    }

    [TestMethod]
    public void Combine_TamperedTag_Throws()
    {
        byte[] secret = { 10, 20, 30, 40 };
        var shares = _splitter.Split(secret, shareCount: 5, threshold: 3);

        // Flip one bit of share 0's tag.
        var tamperedTag = shares[0].Tag;
        tamperedTag[0] ^= 0x01;
        var bad = new AuthenticatedShare(shares[0].Share, shares[0].KeyShare, tamperedTag, shares[0].IssueId);
        var subset = new List<AuthenticatedShare> { bad, shares[1], shares[2] };

        var ex = Assert.ThrowsException<ShareAuthenticationException>(() => _combiner.Combine(subset));
        CollectionAssert.Contains(ex.OffendingShareXs.ToArray(), bad.Share.X);
    }

    [TestMethod]
    public void Combine_TamperedIssueIdOnNonFirstShare_ReportsAsOffender()
    {
        // The combiner uses shares[0] as the authoritative IssueId reference.
        // Flipping IssueId on share index 1 should surface that share's X in OffendingShareXs.
        byte[] secret = { 10, 20, 30 };
        var shares = _splitter.Split(secret, shareCount: 5, threshold: 3);

        var tamperedIssueId = shares[1].IssueId;
        tamperedIssueId[0] ^= 0x01;
        var bad = new AuthenticatedShare(shares[1].Share, shares[1].KeyShare, shares[1].Tag, tamperedIssueId);

        var subset = new List<AuthenticatedShare> { shares[0], bad, shares[2] };
        var ex = Assert.ThrowsException<ShareAuthenticationException>(() => _combiner.Combine(subset));
        CollectionAssert.Contains(ex.OffendingShareXs.ToArray(), bad.Share.X);
    }

    [TestMethod]
    public void Combine_MixedShares_FromTwoSplits_Throws()
    {
        byte[] secret = { 10, 20, 30 };
        var sharesA = _splitter.Split(secret, shareCount: 5, threshold: 3);
        var sharesB = _splitter.Split(secret, shareCount: 5, threshold: 3);

        // Pick X-distinct shares: A[0], A[1] (Xs 1,2), B[2] (X 3).
        var subset = new List<AuthenticatedShare> { sharesA[0], sharesA[1], sharesB[2] };

        var ex = Assert.ThrowsException<ShareAuthenticationException>(() => _combiner.Combine(subset));
        // The B-sourced share has a different IssueId than the reference (sharesA[0]).
        CollectionAssert.Contains(ex.OffendingShareXs.ToArray(), sharesB[2].Share.X);
    }

    [TestMethod]
    public void AuthenticatedShare_ToString_RoundTripsThroughParse()
    {
        byte[] secret = { 7, 14, 21, 28, 35 };
        var shares = _splitter.Split(secret, shareCount: 4, threshold: 2);

        var wire = shares.Select(s => s.ToString()).ToArray();
        var parsed = wire.Select(AuthenticatedShare.Parse).ToList();

        var reconstructed = _combiner.Combine(parsed);
        CollectionAssert.AreEqual(secret, reconstructed);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentNullException))]
    public void AuthenticatedShare_Parse_ThrowsOnEmpty()
    {
        AuthenticatedShare.Parse("");
    }

    [TestMethod]
    [ExpectedException(typeof(FormatException))]
    public void AuthenticatedShare_Parse_ThrowsOnSingleSeparator()
    {
        AuthenticatedShare.Parse("01:00|02:00");
    }

    [TestMethod]
    [ExpectedException(typeof(FormatException))]
    public void AuthenticatedShare_Parse_ThrowsOnFourSeparators()
    {
        AuthenticatedShare.Parse("01:00|02:00|aa|bb|cc");
    }

    [TestMethod]
    [ExpectedException(typeof(FormatException))]
    public void AuthenticatedShare_Parse_ThrowsOnMalformedInnerShare()
    {
        // "ZZ:00" — invalid X — should bubble up as FormatException per implementer's wrap.
        var trailer = new string('0', (16 + 4) * 2);
        AuthenticatedShare.Parse($"ZZ:00|02:00|{trailer}");
    }

    [TestMethod]
    [ExpectedException(typeof(FormatException))]
    public void AuthenticatedShare_Parse_ThrowsOnNonHexTrailer()
    {
        var trailer = new string('G', (16 + 4) * 2);
        AuthenticatedShare.Parse($"01:00|02:00|{trailer}");
    }

    [TestMethod]
    [ExpectedException(typeof(FormatException))]
    public void AuthenticatedShare_Parse_ThrowsOnWrongLengthTrailer()
    {
        // Trailer too short.
        AuthenticatedShare.Parse("01:00|02:00|ABCD");
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void Split_EmptySecret_Throws()
    {
        _splitter.Split(Array.Empty<byte>(), shareCount: 3, threshold: 2);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentOutOfRangeException))]
    public void Split_ThresholdTooSmall_Throws()
    {
        byte[] secret = { 1, 2, 3 };
        _splitter.Split(secret, shareCount: 3, threshold: 1);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentOutOfRangeException))]
    public void Split_ShareCountLessThanThreshold_Throws()
    {
        byte[] secret = { 1, 2, 3 };
        _splitter.Split(secret, shareCount: 2, threshold: 3);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentOutOfRangeException))]
    public void Split_ShareCountAtLeastPrime_Throws()
    {
        var splitter = new AuthenticatedSecretSplitter(prime: 5);
        byte[] secret = { 1, 2 };
        splitter.Split(secret, shareCount: 5, threshold: 2); // shareCount must be < prime
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
        _combiner.Combine(new List<AuthenticatedShare>());
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void Combine_DuplicateX_Throws()
    {
        byte[] secret = { 1, 2, 3 };
        var shares = _splitter.Split(secret, shareCount: 3, threshold: 2);
        _combiner.Combine(new List<AuthenticatedShare> { shares[0], shares[0], shares[1] });
    }

    [TestMethod]
    public void Split_TwoCalls_ProduceDifferentTagsAndKeyShares()
    {
        byte[] secret = { 1, 2, 3, 4, 5 };
        var a = _splitter.Split(secret, shareCount: 3, threshold: 2);
        var b = _splitter.Split(secret, shareCount: 3, threshold: 2);

        // Tags are 16 bytes from HMAC-SHA256 keyed by a fresh 256-bit issue key —
        // collision probability is ~2^-128 per share.
        CollectionAssert.AreNotEqual(a[0].Tag, b[0].Tag);

        // Key shares derive from a fresh random issue key per call — Y-values must differ.
        CollectionAssert.AreNotEqual(a[0].KeyShare.YValues, b[0].KeyShare.YValues);
    }

    [TestMethod]
    public void Combine_AllTagFailures_AreReported_NoShortCircuit()
    {
        byte[] secret = { 10, 20, 30, 40, 50 };
        var shares = _splitter.Split(secret, shareCount: 5, threshold: 3);

        // Flip a bit on the tag of shares 0, 2, 4. Tag tamper preserves IssueId
        // (and the key shares are untouched, so the issue key still reconstructs),
        // so the failure path must be the per-share MAC compare — and all three
        // must be reported, not just the first.
        var bad0 = TamperTag(shares[0]);
        var bad2 = TamperTag(shares[2]);
        var bad4 = TamperTag(shares[4]);

        var subset = new List<AuthenticatedShare> { bad0, shares[1], bad2, shares[3], bad4 };
        var ex = Assert.ThrowsException<ShareAuthenticationException>(() => _combiner.Combine(subset));

        var offendingXs = ex.OffendingShareXs.ToArray();
        CollectionAssert.Contains(offendingXs, bad0.Share.X);
        CollectionAssert.Contains(offendingXs, bad2.Share.X);
        CollectionAssert.Contains(offendingXs, bad4.Share.X);
    }

    [TestMethod]
    public void AuthenticatedShare_ToString_IsSingleLineNoWhitespace()
    {
        byte[] secret = { 1, 2, 3 };
        var shares = _splitter.Split(secret, shareCount: 3, threshold: 2);

        var wire = shares[0].ToString();
        Assert.IsFalse(wire.Contains('\n'), "Wire form must not contain newlines.");
        Assert.IsFalse(wire.Contains('\r'), "Wire form must not contain carriage returns.");
        Assert.IsFalse(wire.Contains(' '), "Wire form must not contain spaces.");
        Assert.IsFalse(wire.Contains('\t'), "Wire form must not contain tabs.");
    }

    // ---- helpers ----

    private static AuthenticatedShare TamperShareY(AuthenticatedShare original, int yIndex, int prime)
    {
        var ys = (int[])original.Share.YValues.Clone();
        ys[yIndex] = (ys[yIndex] + 1) % prime;
        var newShare = new Share(original.Share.X, ys);
        return new AuthenticatedShare(newShare, original.KeyShare, original.Tag, original.IssueId);
    }

    private static AuthenticatedShare TamperTag(AuthenticatedShare original)
    {
        var tag = original.Tag;
        tag[0] ^= 0x01;
        return new AuthenticatedShare(original.Share, original.KeyShare, tag, original.IssueId);
    }
}
