using System.Security.Cryptography;

namespace ShamirSecretSharing;

/// <summary>
/// Polynomial-shaped helpers for Shamir's Secret Sharing. Hides the polynomial
/// representation: callers see only secret bytes, x-coordinates, and y-values.
/// </summary>
internal static class SecretPolynomial
{
    /// <summary>
    /// Builds a degree-(threshold-1) polynomial with constant term equal to
    /// <paramref name="secretByte"/> and threshold-1 random coefficients, then
    /// evaluates it at each x in <paramref name="xs"/>.
    /// </summary>
    public static int[] SampleAndEvaluate(
        int secretByte,
        int threshold,
        ReadOnlySpan<int> xs,
        FiniteField field,
        RandomNumberGenerator rng)
    {
        var coefficients = new int[threshold];
        coefficients[0] = secretByte;

        if (threshold > 1)
        {
            var randomBytes = new byte[threshold - 1];
            rng.GetBytes(randomBytes);
            for (var i = 1; i < threshold; i++)
                coefficients[i] = randomBytes[i - 1] % field.Prime;
        }

        var ys = new int[xs.Length];
        for (var i = 0; i < xs.Length; i++)
        {
            var x = xs[i];
            var result = 0;
            var powerOfX = 1;
            foreach (var coeff in coefficients)
            {
                result = field.Add(result, field.Multiply(coeff, powerOfX));
                powerOfX = field.Multiply(powerOfX, x);
            }
            ys[i] = result;
        }
        return ys;
    }

    /// <summary>
    /// Lagrange interpolation at x = 0 over the (xs[i], ys[i]) points.
    /// Spans must have the same length.
    /// </summary>
    public static int InterpolateAtZero(
        ReadOnlySpan<int> xs,
        ReadOnlySpan<int> ys,
        FiniteField field)
    {
        if (xs.Length != ys.Length)
            throw new ArgumentException($"xs and ys must have the same length (xs={xs.Length}, ys={ys.Length}).");

        var result = 0;
        for (var i = 0; i < xs.Length; i++)
        {
            var xi = xs[i];
            var numerator = 1;
            var denominator = 1;
            for (var j = 0; j < xs.Length; j++)
            {
                if (i == j) continue;
                var xj = xs[j];
                numerator = field.Multiply(numerator, xj);
                denominator = field.Multiply(denominator, field.Subtract(xj, xi));
            }
            var basis = field.Divide(numerator, denominator);
            result = field.Add(result, field.Multiply(ys[i], basis));
        }
        return result;
    }
}
