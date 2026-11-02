using ShamirSecretSharing;

namespace ShamirSecretSharingTests;

[TestClass]
public class ShareSerializationTests
{
    [TestMethod]
    public void Share_Serialization_ParsesHexFormats()
    {
        // 1-digit (should be padded), 2-digit, 3-digit, 4-digit, and edge case: first is 3+ digits
        var share = new Share(1, new[] { 0x0, 0xA, 0x10, 0x100, 0x1F4, 0xFF, 0x1000 });
        var str = share.ToString();
        // X=01, YValues: 00 0A 10 ,100, ,1F4, FF ,1000,
        Assert.AreEqual("01:000A10,100,,1F4,FF,1000,", str);

        var parsed = Share.Parse(str);
        Assert.AreEqual(1, parsed.X);
        CollectionAssert.AreEqual(new[] { 0x0, 0xA, 0x10, 0x100, 0x1F4, 0xFF, 0x1000 }, parsed.YValues);

        // Edge case: first Y is 3+ digits
        var share2 = new Share(0xAB, new[] { 0x123, 0x4, 0x56 });
        var str2 = share2.ToString();
        Assert.AreEqual("AB:,123,0456", str2);
        var parsed2 = Share.Parse(str2);
        Assert.AreEqual(0xAB, parsed2.X);
        CollectionAssert.AreEqual(new[] { 0x123, 0x4, 0x56 }, parsed2.YValues);
    }

    [TestMethod]
    public void Share_Parse_ThrowsOnNull()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            Share.Parse(null!);
        });
    }

    [TestMethod]
    public void Share_Parse_ThrowsOnEmpty()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            Share.Parse("");
        });
    }

    [TestMethod]
    public void Share_Parse_ThrowsOnMissingColon()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            Share.Parse("01AA");
        });
    }

    [TestMethod]
    public void Share_Parse_ThrowsOnInvalidX()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            Share.Parse("ZZ:00");
        });
    }

    [TestMethod]
    public void Share_Parse_ThrowsOnInvalidY()
    {
        Assert.ThrowsExactly<FormatException>(() =>
        {
            Share.Parse("01:GG");
        });
    }

    [TestMethod]
    public void Share_Parse_ThrowsOnUnmatchedComma()
    {
        Assert.ThrowsExactly<FormatException>(() =>
        {
            Share.Parse("01:,123");
        });
    }
}
