using System.Text;
using System.Globalization;
using System.Linq; // Added for LINQ's Select and ToArray

namespace ShamirSecretSharing;

/// <summary>
/// Represents a single share in Shamir's Secret Sharing scheme.
/// </summary>
/// <remarks>
/// Each share consists of a unique, non-zero x-coordinate and an array of y-coordinates
/// corresponding to the secret's bytes or integer values.
/// The string representation of a share is "X_hex:Y0_hex:Y1_hex:...:YN_hex".
/// </remarks>
public record Share
{
    /// <summary>
    /// Gets the x-coordinate of the share.
    /// Must be unique and non-zero for each share.
    /// </summary>
    public int X { get; }

    /// <summary>
    /// Gets the array of y-coordinates for the share.
    /// Each element corresponds to a byte or integer of the secret.
    /// </summary>
    public int[] YValues { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Share"/> record.
    /// </summary>
    /// <param name="X">The unique, non-zero x-coordinate of the share.</param>
    /// <param name="YValues">The array of y-coordinates for the share.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="YValues"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="YValues"/> is empty.</exception>
    public Share(int X, int[] YValues)
    {
        if (YValues == null)
            throw new ArgumentNullException(nameof(YValues));
        // Per problem description, secrets (and thus YValues) are not allowed to be empty.
        // This check should ideally be in ShamirSecretSharingService when splitting,
        // but adding here for robustness of the Share object itself.
        if (YValues.Length == 0)
            throw new ArgumentException("YValues cannot be empty.", nameof(YValues));

        this.X = X;
        this.YValues = YValues;
    }

    /// <summary>
    /// Deconstructs the share into its components.
    /// </summary>
    /// <param name="x">The x-coordinate of the share.</param>
    /// <param name="yValues">The array of y-coordinates for the share.</param>
    public void Deconstruct(out int x, out int[] yValues)
    {
        x = X;
        yValues = YValues;
    }

    /// <summary>
    /// Serializes the share to a string representation using colon-delimited hexadecimal values.
    /// Format: X_hex:Y0_hex:Y1_hex:...:YN_hex
    /// Example: new Share(10, new[] {255, 1, 16}) produces "A:FF:1:10".
    /// </summary>
    /// <returns>A string representation of the share.</returns>
    public override string ToString()
    {
        // Start with X in hex
        var parts = new List<string> { X.ToString("X", CultureInfo.InvariantCulture) };
        // Add all YValues in hex
        parts.AddRange(YValues.Select(y => y.ToString("X", CultureInfo.InvariantCulture)));
        return string.Join(":", parts);
    }

    /// <summary>
    /// Deserializes a share from its string representation.
    /// Format: X_hex:Y0_hex:Y1_hex:...:YN_hex
    /// </summary>
    /// <param name="shareString">The string representation of the share.</param>
    /// <returns>A <see cref="Share"/> object.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="shareString"/> is null or empty.</exception>
    /// <exception cref="FormatException">
    /// Thrown if <paramref name="shareString"/> is not in the expected format,
    /// if any part is not a valid hexadecimal number, or if there are not enough parts
    /// (e.g., missing Y values or X value).
    /// </exception>
    public static Share Parse(string shareString)
    {
        if (string.IsNullOrEmpty(shareString))
            throw new ArgumentNullException(nameof(shareString), "Share string cannot be null or empty.");

        var parts = shareString.Split(':');

        // Must have at least X and one Y value.
        if (parts.Length < 2)
            throw new FormatException($"Invalid share string format. Expected at least two parts (X:Y0), got {parts.Length} parts. String: \"{shareString}\"");

        int x;
        try
        {
            x = int.Parse(parts[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }
        catch (FormatException ex)
        {
            throw new FormatException($"Invalid X value '{parts[0]}' in share string. Expected a hexadecimal number.", ex);
        }
        catch (OverflowException ex)
        {
            throw new FormatException($"X value '{parts[0]}' is out of range for an Int32.", ex);
        }


        var yValues = new int[parts.Length - 1];
        for (var i = 1; i < parts.Length; i++)
        {
            try
            {
                yValues[i - 1] = int.Parse(parts[i], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }
            catch (FormatException ex)
            {
                throw new FormatException($"Invalid Y value '{parts[i]}' at index {i-1} in share string. Expected a hexadecimal number.", ex);
            }
            catch (OverflowException ex)
            {
                 throw new FormatException($"Y value '{parts[i]}' at index {i-1} is out of range for an Int32.", ex);
            }
        }

        // The constructor Share(int X, int[] YValues) already checks if YValues is empty.
        // If parts.Length was 1 (e.g. "A"), it would have failed the parts.Length < 2 check.
        // If parts.Length was 2 (e.g. "A:"), parts[1] would be "" and int.Parse would throw FormatException.
        // This is handled by the try-catch for Y values.
        // If YValues ends up empty due to an unexpected split result (e.g. "A:" leading to parts=["A",""]),
        // the int.Parse for yValues[0] will fail.
        // An explicit check here like `if (yValues.Length == 0)` is redundant due to `parts.Length < 2`
        // and the Share constructor's own validation, assuming `string.Split` behavior.

        return new Share(x, yValues);
    }
}
