using ShamirSecretSharing;

namespace ShamirSecretSharingTests;

[TestClass]
public class FiniteFieldTests
{
    [TestMethod]
    public void FiniteField_Add()
    {
        var ff = new FiniteField(257);
        Assert.AreEqual(5, ff.Add(2, 3));
        Assert.AreEqual(0, ff.Add(256, 1));
        Assert.AreEqual(255, ff.Add(250, 5));
    }

    [TestMethod]
    public void FiniteField_Subtract()
    {
        var ff = new FiniteField(257);
        Assert.AreEqual(256, ff.Subtract(2, 3)); // 2 - 3 = -1 = 256 mod 257
        Assert.AreEqual(1, ff.Subtract(5, 4));
        Assert.AreEqual(0, ff.Subtract(10, 10));
    }

    [TestMethod]
    public void FiniteField_Multiply()
    {
        var ff = new FiniteField(257);
        Assert.AreEqual(6, ff.Multiply(2, 3));
        // Corrected assertion: 256*256 mod 257 = (-1)*(-1) mod 257 = 1
        Assert.AreEqual(1, ff.Multiply(256, 256));
        Assert.AreEqual(230, ff.Multiply(10, 23)); // 230 % 257 = 230
        Assert.AreEqual(230 % 257, ff.Multiply(10, 23)); // Redundant check, but fine
        Assert.AreEqual(243, ff.Multiply(20, 25)); // 500 mod 257 = 243
        Assert.AreEqual(500 % 257, ff.Multiply(20, 25)); // Also correct
    }

    [TestMethod]
    public void FiniteField_PowerAndInverse()
    {
        var ff = new FiniteField(257);
        // 2^3 = 8
        Assert.AreEqual(8, ff.Power(2, 3));
        // 2^-1 mod 257. 2 * 129 = 258 = 1 mod 257. So 2^-1 = 129
        Assert.AreEqual(129, ff.Inverse(2));
        Assert.AreEqual(1, ff.Multiply(2, ff.Inverse(2)));
        Assert.AreEqual(1, ff.Multiply(15, ff.Inverse(15)));
    }

    [TestMethod]
    public void FiniteField_Divide()
    {
        var ff = new FiniteField(257);
        // 6 / 2 = 3
        Assert.AreEqual(3, ff.Divide(6, 2));
        // 7 / 2 = 7 * 129 = 903. 903 mod 257 = 903 - 3*257 = 903 - 771 = 132.
        Assert.AreEqual(132, ff.Divide(7, 2));
        Assert.AreEqual(7, ff.Multiply(132, 2));
    }
}
