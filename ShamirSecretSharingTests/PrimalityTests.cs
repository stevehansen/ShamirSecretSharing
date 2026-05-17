using ShamirSecretSharing;

namespace ShamirSecretSharingTests;

[TestClass]
public class PrimalityTests
{
    [DataTestMethod]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(257)]
    [DataRow(65537)]
    [DataRow(int.MaxValue)] // 2^31 - 1, a Mersenne prime
    public void IsPrime_ReturnsTrue_ForKnownPrimes(int prime)
    {
        Assert.IsTrue(Primality.IsPrime(prime));
    }

    [DataTestMethod]
    [DataRow(4)]
    [DataRow(9)]
    [DataRow(25)]
    [DataRow(91)] // 7 * 13 — Miller-Rabin strong-liar trap
    [DataRow(256)]
    [DataRow(int.MaxValue - 1)]
    public void IsPrime_ReturnsFalse_ForComposites(int composite)
    {
        Assert.IsFalse(Primality.IsPrime(composite));
    }

    // Carmichael numbers — composite, but pass a naive Fermat primality test for every
    // base coprime to n. Miller-Rabin with witnesses {2, 7, 61} catches them.
    [DataTestMethod]
    [DataRow(561)]
    [DataRow(1105)]
    [DataRow(1729)]
    [DataRow(2465)]
    [DataRow(2821)]
    [DataRow(6601)]
    [DataRow(8911)]
    public void IsPrime_ReturnsFalse_ForCarmichaelNumbers(int carmichael)
    {
        Assert.IsFalse(Primality.IsPrime(carmichael));
    }

    [DataTestMethod]
    [DataRow(-1)]
    [DataRow(0)]
    [DataRow(1)]
    public void IsPrime_ReturnsFalse_ForValuesLessThanTwo(int value)
    {
        Assert.IsFalse(Primality.IsPrime(value));
    }
}
