using System.Text;
using System.Globalization;

namespace ShamirSecretSharing;

/// <summary>
/// Represents a single share in Shamir's Secret Sharing scheme.
/// </summary>
/// <remarks>
/// Each share consists of a unique, non-zero x-coordinate and an array of y-coordinates
/// corresponding to the secret's bytes or integer values.
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
    public Share(int X, int[] YValues)
    {
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
    /// Serializes the share to a compact string representation.
    /// Format: X:Y0Y1Y2... (each Y as 2 hex digits, unless 3+ hex digits, then wrap with commas)
    /// </summary>
    /// <returns>A string representation of the share.</returns>
    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.Append(X.ToString("X"));
        sb.Append(':');
        foreach (var y in YValues)
        {
            var hex = y.ToString("X");
            switch (hex.Length)
            {
                case 1:
                    sb.Append('0').Append(hex); // pad single digit
                    break;

                case 2:
                    sb.Append(hex);
                    break;

                default:
                    sb.Append(',').Append(hex).Append(',');
                    break;
            }
        }
        return sb.ToString();
    }

    /// <summary>
    /// Deserializes a share from its string representation.
    /// </summary>
    /// <param name="shareString">The string representation of the share.</param>
    /// <returns>A <see cref="Share"/> object.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="shareString"/> is null or empty.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="shareString"/> is not in the expected format.</exception>
    /// <exception cref="FormatException">Thrown if <paramref name="shareString"/> is not in the expected format.</exception>
    public static Share Parse(string shareString)
    {
        if (string.IsNullOrEmpty(shareString))
            throw new ArgumentNullException(nameof(shareString));

        var parts = shareString.Split(':', 2);
        if (parts.Length != 2)
            throw new ArgumentException($"Share string must contain one ':' separator for X and YValues.\nshareString = {shareString}", nameof(shareString));

        // Parse X as hexadecimal
        if (!int.TryParse(parts[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var x))
            throw new ArgumentException($"Invalid X value in share string.\nX = {parts[0]}", nameof(shareString));

        if (string.IsNullOrEmpty(parts[1]))
            throw new ArgumentException("YValues cannot be empty.", nameof(shareString));

        var yList = new List<int>();
        var s = parts[1];
        var pos = 0;
        while (pos < s.Length)
        {
            if (s[pos] == ',')
            {
                // 3+ hex digits, wrapped in commas
                var nextComma = s.IndexOf(',', pos + 1);
                if (nextComma == -1)
                    throw new FormatException("Unmatched comma in YValues section.");
                var hex = s.Substring(pos + 1, nextComma - pos - 1);
                if (!int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var y))
                    throw new FormatException($"Invalid Y value '{hex}' in share string.");
                yList.Add(y);
                pos = nextComma + 1;
            }
            else
            {
                // Always 2 hex digits
                if (pos + 2 > s.Length)
                    throw new FormatException("Unexpected end of YValues section.");
                var hex = s.Substring(pos, 2);
                if (!int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var y))
                    throw new FormatException($"Invalid Y value '{hex}' in share string.");
                yList.Add(y);
                pos += 2;
            }
        }
        return new(x, yList.ToArray());
    }
}
