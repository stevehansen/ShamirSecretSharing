namespace ShamirSecretSharing;

/// <summary>
/// Handles arithmetic operations in a Galois Field GF(prime).
/// </summary>
public class FiniteField
{
    /// <summary>
    /// Gets the prime modulus of the finite field.
    /// </summary>
    public int Prime { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="FiniteField"/> class with the specified prime modulus.
    /// </summary>
    /// <param name="prime">The prime modulus for the field. This value **MUST** be a prime number.</param>
    /// <remarks>
    /// **WARNING: CRITICAL SECURITY REQUIREMENT!**
    /// The <paramref name="prime"/> parameter **MUST** be a prime number.
    /// If <paramref name="prime"/> is not a prime number:
    /// 1.  The mathematical structure used is no longer a finite field (specifically, it's not a Galois Field GF(p)).
    /// 2.  Multiplicative inverses, which are essential for Lagrange interpolation during secret reconstruction
    ///     (via the <see cref="ReconstructSecret"/> method in <see cref="ShamirSecretSharingService"/>),
    ///     may not exist for all non-zero elements, or they will be calculated incorrectly by the <see cref="Inverse(int)"/>
    ///     method, as its implementation relies on Fermat's Little Theorem which only holds if <paramref name="prime"/> is prime.
    /// 3.  The security guarantees of Shamir's Secret Sharing are completely **VOIDED**. This could lead to:
    ///     a.  The secret being reconstructible with fewer shares than the specified threshold `t`.
    ///     b.  Complete failure of the reconstruction process, resulting in data loss.
    ///     c.  Other unpredictable and insecure behaviors.
    ///
    /// This class performs only a rudimentary check (`prime > 1`) and **DOES NOT** implement a robust primality test.
    /// It is the **CALLER'S RESPONSIBILITY** to ensure that the provided <paramref name="prime"/> is indeed a prime number.
    ///
    /// **Recommendation:** Use well-known prime numbers suitable for your application's data range (e.g., 257 for byte data)
    /// or perform an independent, cryptographically sound primality test on the chosen value before using it
    /// with this library. Failure to do so can lead to catastrophic security failures.
    /// </remarks>
    /// <exception cref="ArgumentException">Thrown if prime is less than or equal to 1.</exception>
    public FiniteField(int prime)
    {
        // WARNING: This is NOT a primality test. It is the caller's responsibility to ensure 'prime' is a prime number.
        // See the XML documentation for this constructor for critical security information regarding this parameter.
        if (prime <= 1) throw new ArgumentException("Input value must be greater than 1. It is also REQUIRED to be a prime number.", nameof(prime));
        
        // For the security of Shamir's Secret Sharing, 'prime' MUST be a prime number.
        // If 'prime' is not prime, the mathematical properties required for SSS are lost,
        // potentially allowing secret reconstruction with fewer shares or other failures.
        // This class assumes 'prime' is prime for its operations (e.g., Inverse method).
        // The default value (257) used by ShamirSecretSharingService is a known prime.
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
    /// <remarks>This method relies on Fermat's Little Theorem and assumes <see cref="Prime"/> is a prime number.</remarks>
    public int Inverse(int n)
    {
        if (n == 0) throw new ArgumentException("Cannot compute inverse of 0.");
        // This calculation (Fermat's Little Theorem for inverse: a^(p-2) mod p)
        // is only valid if Prime is indeed a prime number.
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