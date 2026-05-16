using System.Security.Cryptography;

namespace ShamirSecretSharing;

/// <summary>
/// Polynomial-shaped helpers for Shamir's Secret Sharing. Hides the polynomial
/// representation: callers see only secret bytes, x-coordinates, and y-values.
/// </summary>
internal static class SecretPolynomial
{
    private const int StackallocThreshold = 64;

    /// <summary>
    /// Builds a degree-(threshold-1) polynomial with constant term equal to
    /// <paramref name="secretByte"/> and threshold-1 unbiased random coefficients,
    /// then evaluates it at each x in <paramref name="xs"/>, writing the results
    /// into <paramref name="ys"/>. <paramref name="xs"/> and <paramref name="ys"/>
    /// must have the same length.
    /// </summary>
    public static void SampleAndEvaluate(
        int secretByte,
        int threshold,
        ReadOnlySpan<int> xs,
        Span<int> ys,
        FiniteField field)
    {
        if (xs.Length != ys.Length)
            throw new ArgumentException($"xs and ys must have the same length (xs={xs.Length}, ys={ys.Length}).");

        Span<int> coefficients = threshold <= StackallocThreshold
            ? stackalloc int[threshold]
            : new int[threshold];
        coefficients[0] = secretByte;
        for (var i = 1; i < threshold; i++)
            coefficients[i] = RandomNumberGenerator.GetInt32(field.Prime);

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
    }

    /// <summary>
    /// Precomputes the Lagrange basis values L_i(0) for the given x-coordinates.
    /// Splitting interpolation into basis precomputation plus per-byte application
    /// drops reconstruction from O(L*t^2) to O(t^2 + L*t).
    /// </summary>
    public static int[] ComputeLagrangeBasisAtZero(ReadOnlySpan<int> xs, FiniteField field)
    {
        var basis = new int[xs.Length];
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
            basis[i] = field.Divide(numerator, denominator);
        }
        return basis;
    }

    /// <summary>
    /// Applies a precomputed Lagrange basis (from <see cref="ComputeLagrangeBasisAtZero"/>)
    /// to the given y-values, yielding P(0). <paramref name="ys"/> and
    /// <paramref name="basis"/> must have the same length.
    /// </summary>
    public static int InterpolateWithBasis(ReadOnlySpan<int> ys, ReadOnlySpan<int> basis, FiniteField field)
    {
        if (ys.Length != basis.Length)
            throw new ArgumentException($"ys and basis must have the same length (ys={ys.Length}, basis={basis.Length}).");

        var result = 0;
        for (var i = 0; i < ys.Length; i++)
            result = field.Add(result, field.Multiply(ys[i], basis[i]));
        return result;
    }

    /// <summary>
    /// Lagrange interpolation at x = 0 over the (xs[i], ys[i]) points.
    /// Convenience composition of <see cref="ComputeLagrangeBasisAtZero"/> and
    /// <see cref="InterpolateWithBasis"/>; prefer the split form when interpolating
    /// many y-vectors over the same x-coordinates.
    /// </summary>
    public static int InterpolateAtZero(
        ReadOnlySpan<int> xs,
        ReadOnlySpan<int> ys,
        FiniteField field)
    {
        if (xs.Length != ys.Length)
            throw new ArgumentException($"xs and ys must have the same length (xs={xs.Length}, ys={ys.Length}).");

        var basis = ComputeLagrangeBasisAtZero(xs, field);
        return InterpolateWithBasis(ys, basis, field);
    }
}
