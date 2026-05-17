using System.Buffers.Binary;

namespace ShamirSecretSharing;

/// <summary>
/// Produces the fixed big-endian byte layout HMAC'd by the authenticated
/// split/combine path. Independent of textual encoding so whitespace, case,
/// or alternative serializations of the same <see cref="Share"/> all yield
/// the same tag input.
/// </summary>
internal static class CanonicalShareBytes
{
    /// <summary>
    /// Encodes <paramref name="share"/> as <c>BigEndian(X, 4) || BigEndian(YLen, 4) || foreach Y: BigEndian(Y, 4)</c>.
    /// </summary>
    public static byte[] Encode(Share share)
    {
        var ys = share.YValues;
        var buffer = new byte[8 + (ys.Length * 4)];
        BinaryPrimitives.WriteInt32BigEndian(buffer.AsSpan(0, 4), share.X);
        BinaryPrimitives.WriteInt32BigEndian(buffer.AsSpan(4, 4), ys.Length);
        for (var i = 0; i < ys.Length; i++)
            BinaryPrimitives.WriteInt32BigEndian(buffer.AsSpan(8 + (i * 4), 4), ys[i]);
        return buffer;
    }
}
