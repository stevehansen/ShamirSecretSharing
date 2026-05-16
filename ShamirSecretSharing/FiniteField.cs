namespace ShamirSecretSharing;

/// <summary>
/// Handles arithmetic operations in a Galois Field GF(prime).
/// </summary>
public class FiniteField
{
    internal const int DefaultPrime = 257; // Smallest prime > 255
    internal const int StackallocThreshold = 256;

    /// <summary>
    /// Gets the prime modulus of the finite field.
    /// </summary>
    public int Prime { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="FiniteField"/> class with the specified prime modulus.
    /// </summary>
    /// <param name="prime">The prime modulus for the field. Must be a prime number.</param>
    public FiniteField(int prime)
    {
        // Rudimentary prime check for this example.
        // In a real-world scenario, use a robust primality test or known cryptographic primes.
        if (prime <= 1) throw new ArgumentException("Prime must be greater than 1.");
        // For simplicity, we'll assume the provided number is prime.
        // For p=257, it is indeed prime.
        Prime = prime;
    }

    /// <summary>
    /// Adds two elements in the field.
    /// </summary>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <returns>The sum (a + b) modulo <see cref="Prime"/>.</returns>
    public int Add(int a, int b) => (a + b) % Prime;

    /// <summary>
    /// Subtracts one element from another in the field.
    /// </summary>
    /// <param name="a">The minuend.</param>
    /// <param name="b">The subtrahend.</param>
    /// <returns>The difference (a - b) modulo <see cref="Prime"/>.</returns>
    public int Subtract(int a, int b) => (a - b % Prime + Prime) % Prime;

    /// <summary>
    /// Multiplies two elements in the field.
    /// </summary>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <returns>The product (a * b) modulo <see cref="Prime"/>.</returns>
    public int Multiply(int a, int b) => (int)(((long)a * b) % Prime); // Use long for intermediate to prevent overflow

    /// <summary>
    /// Raises a base value to an exponent in the field.
    /// </summary>
    /// <param name="baseVal">The base value.</param>
    /// <param name="exp">The exponent.</param>
    /// <returns>The result of (baseVal ^ exp) modulo <see cref="Prime"/>.</returns>
    public int Power(int baseVal, int exp)
    {
        var res = 1;
        baseVal %= Prime;
        while (exp > 0)
        {
            if (exp % 2 == 1) res = Multiply(res, baseVal);
            baseVal = Multiply(baseVal, baseVal);
            exp /= 2;
        }
        return res;
    }

    /// <summary>
    /// Computes the multiplicative inverse of an element in the field.
    /// </summary>
    /// <param name="n">The element to invert.</param>
    /// <returns>The multiplicative inverse of <paramref name="n"/> modulo <see cref="Prime"/>.</returns>
    public int Inverse(int n)
    {
        if (n == 0) throw new ArgumentException("Cannot compute inverse of 0.");
        return Power(n, Prime - 2);
    }

    /// <summary>
    /// Divides one element by another in the field.
    /// </summary>
    /// <param name="a">The dividend.</param>
    /// <param name="b">The divisor.</param>
    /// <returns>The result of (a / b) modulo <see cref="Prime"/>.</returns>
    public int Divide(int a, int b)
    {
        if (b == 0) throw new ArgumentException("Cannot divide by zero.");
        return Multiply(a, Inverse(b));
    }
}