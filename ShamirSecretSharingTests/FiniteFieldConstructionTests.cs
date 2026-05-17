using System.Reflection;
using ShamirSecretSharing;

namespace ShamirSecretSharingTests;

[TestClass]
public class FiniteFieldConstructionTests
{
    [DataTestMethod]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(257)]
    [DataRow(65537)]
    [DataRow(int.MaxValue)] // 2^31 - 1, a Mersenne prime
    public void Constructor_AcceptsKnownPrimes(int prime)
    {
        var field = new FiniteField(prime);
        Assert.AreEqual(prime, field.Prime);
    }

    [DataTestMethod]
    [DataRow(4)]
    [DataRow(9)]
    [DataRow(25)]
    [DataRow(91)] // 7 * 13 — Miller-Rabin strong-liar trap
    [DataRow(256)]
    [DataRow(int.MaxValue - 1)]
    public void Constructor_RejectsComposites(int composite)
    {
        Assert.ThrowsException<ArgumentException>(() => new FiniteField(composite));
    }

    // Carmichael numbers — composite, but pass a naive Fermat primality test for every
    // base coprime to n. They are the canonical reason we rely on Miller-Rabin, not Fermat.
    [DataTestMethod]
    [DataRow(561)]
    [DataRow(1105)]
    [DataRow(1729)]
    [DataRow(2465)]
    [DataRow(2821)]
    [DataRow(6601)]
    [DataRow(8911)]
    public void Constructor_RejectsCarmichaelNumbers(int carmichael)
    {
        Assert.ThrowsException<ArgumentException>(() => new FiniteField(carmichael));
    }

    [DataTestMethod]
    [DataRow(-1)]
    [DataRow(0)]
    [DataRow(1)]
    public void Constructor_RejectsValuesLessThanTwo(int value)
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => new FiniteField(value));
    }

    [TestMethod]
    public void Default_IsSingleton()
    {
        var first = FiniteField.Default;
        var second = FiniteField.Default;
        Assert.AreSame(first, second);
    }

    [TestMethod]
    public void Default_HasPrime257()
    {
        Assert.AreEqual(257, FiniteField.Default.Prime);
    }

    [TestMethod]
    public void SecretSplitter_DefaultCtor_ReusesDefaultField()
    {
        var splitter = new SecretSplitter();
        var field = GetField(splitter, "_field");
        Assert.AreSame(FiniteField.Default, field);
    }

    [TestMethod]
    public void SecretSplitter_CustomPrime_DoesNotReuseDefaultField()
    {
        var splitter = new SecretSplitter(prime: 263);
        var field = GetField(splitter, "_field");
        Assert.AreNotSame(FiniteField.Default, field);
        Assert.AreEqual(263, field.Prime);
    }

    [TestMethod]
    public void SecretCombiner_DefaultCtor_ReusesDefaultField()
    {
        var combiner = new SecretCombiner();
        var field = GetField(combiner, "_field");
        Assert.AreSame(FiniteField.Default, field);
    }

    [TestMethod]
    public void SecretCombiner_CustomPrime_DoesNotReuseDefaultField()
    {
        var combiner = new SecretCombiner(prime: 263);
        var field = GetField(combiner, "_field");
        Assert.AreNotSame(FiniteField.Default, field);
        Assert.AreEqual(263, field.Prime);
    }

    private static FiniteField GetField(object instance, string fieldName)
    {
        var info = instance.GetType().GetField(fieldName, BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.IsNotNull(info, $"Expected private field '{fieldName}' on {instance.GetType().Name}.");
        var value = info.GetValue(instance);
        Assert.IsInstanceOfType(value, typeof(FiniteField));
        return (FiniteField)value!;
    }
}
