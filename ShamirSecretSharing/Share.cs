using System.Text;

namespace ShamirSecretSharing;

/// <summary>
/// Represents a single share.
/// X is the x-coordinate (must be unique and non-zero for each share).
/// YValues is an array of y-coordinates, one for each byte of the secret.
/// </summary>
public record Share(int X, int[] YValues)
{
    public override string ToString()
    {
        // Provides a human-readable string, good for debugging.
        // For actual storage/transport, SerializeToString is likely better.
        return $"Share(X={X}, YValues=[{string.Join(",", YValues)}])";
    }

    /// <summary>
    /// Serializes the share to a compact string representation.
    /// Format: X:Y0,Y1,Y2,...
    /// </summary>
    /// <returns>A string representation of the share.</returns>
    public string SerializeToString()
    {
        // Using simple decimal representation for X and Y values.
        // Base64 encoding of a binary format would be more compact for large Y values or many Y values.
        var sb = new StringBuilder();
        sb.Append(X);
        sb.Append(':');
        for (var i = 0; i < YValues.Length; i++)
        {
            sb.Append(YValues[i]);
            if (i < YValues.Length - 1)
            {
                sb.Append(',');
            }
        }
        return sb.ToString();
    }

    /// <summary>
    /// Deserializes a share from its string representation.
    /// </summary>
    /// <param name="shareString">The string representation of the share.</param>
    /// <returns>A Share object.</returns>
    /// <exception cref="ArgumentNullException">If shareString is null or empty.</exception>
    /// <exception cref="FormatException">If the shareString is not in the expected format.</exception>
    public static Share DeserializeFromString(string shareString)
    {
        if (string.IsNullOrEmpty(shareString))
            throw new ArgumentNullException(nameof(shareString));

        var parts = shareString.Split(':');
        if (parts.Length != 2)
            throw new FormatException("Share string must contain one ':' separator for X and YValues.");

        if (!int.TryParse(parts[0], out var x))
            throw new FormatException("Invalid X value in share string.");

        if (string.IsNullOrEmpty(parts[1])) // Handle case of empty secret (YValues is empty array)
        {
            return new(x, []);
        }

        var yValueStrings = parts[1].Split(',');
        var yValues = new int[yValueStrings.Length];
        for (var i = 0; i < yValueStrings.Length; i++)
        {
            if (!int.TryParse(yValueStrings[i], out yValues[i]))
                throw new FormatException($"Invalid Y value '{yValueStrings[i]}' at index {i} in share string.");
        }
        return new(x, yValues);
    }
}
