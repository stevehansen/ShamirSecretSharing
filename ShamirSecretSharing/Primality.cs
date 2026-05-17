namespace ShamirSecretSharing;

/// <summary>
/// Primality testing utilities for 32-bit integers.
/// </summary>
internal static class Primality
{
    /// <summary>
    /// Deterministic primality test for 32-bit integers via Miller-Rabin with
    /// witnesses {2, 7, 61} (Jaeschke 1993 — sufficient for all n &lt; 2^32).
    /// </summary>
    /// <param name="n">The integer to test.</param>
    /// <returns><c>true</c> if <paramref name="n"/> is prime; otherwise <c>false</c>.</returns>
    internal static bool IsPrime(int n)
    {
        if (n < 2) return false;
        if (n == 2 || n == 3) return true;
        if (n % 2 == 0) return false;

        // Write n - 1 = d * 2^r with d odd.
        var d = n - 1;
        var r = 0;
        while ((d & 1) == 0)
        {
            d >>= 1;
            r++;
        }

        foreach (var a in (ReadOnlySpan<int>)[2, 7, 61])
        {
            if (a >= n) continue;
            if (!MillerRabinPasses(n, d, r, a)) return false;
        }
        return true;
    }

    private static bool MillerRabinPasses(int n, int d, int r, int a)
    {
        var x = ModPow(a, d, n);
        if (x == 1 || x == n - 1) return true;

        for (var i = 0; i < r - 1; i++)
        {
            x = (int)(((long)x * x) % n);
            if (x == n - 1) return true;
        }
        return false;
    }

    private static int ModPow(int baseVal, int exp, int mod)
    {
        long result = 1;
        long b = baseVal % mod;
        while (exp > 0)
        {
            if ((exp & 1) == 1)
                result = (result * b) % mod;
            b = (b * b) % mod;
            exp >>= 1;
        }
        return (int)result;
    }
}
