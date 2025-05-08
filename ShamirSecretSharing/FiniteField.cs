namespace ShamirSecretSharing;

/// <summary>
/// Handles arithmetic operations in a Galois Field GF(prime).
/// </summary>
public class FiniteField
{
    public int Prime { get; }

    public FiniteField(int prime)
    {
        // Rudimentary prime check for this example.
        // In a real-world scenario, use a robust primality test or known cryptographic primes.
        if (prime <= 1) throw new ArgumentException("Prime must be greater than 1.");
        // For simplicity, we'll assume the provided number is prime.
        // For p=257, it is indeed prime.
        Prime = prime;
    }

    public int Add(int a, int b) => (a + b) % Prime;

    public int Subtract(int a, int b) => (a - b % Prime + Prime) % Prime;

    public int Multiply(int a, int b) => (int)(((long)a * b) % Prime); // Use long for intermediate to prevent overflow

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

    // Fermat's Little Theorem: a^(p-1) % p = 1 => a^(p-2) % p = a^(-1) % p
    public int Inverse(int n)
    {
        if (n == 0) throw new ArgumentException("Cannot compute inverse of 0.");
        return Power(n, Prime - 2);
    }

    public int Divide(int a, int b)
    {
        if (b == 0) throw new ArgumentException("Cannot divide by zero.");
        return Multiply(a, Inverse(b));
    }
}