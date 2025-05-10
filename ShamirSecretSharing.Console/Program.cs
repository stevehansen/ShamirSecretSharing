using ShamirSecretSharing;

var sss = new ShamirSecretSharingService(); // Defaults to prime 257

var originalSecret = "This is a very secret message!";
Console.WriteLine($"Original Secret: {originalSecret}");

var n = 5; // Total shares
var t = 3; // Threshold to reconstruct

Console.WriteLine($"Splitting into {n} shares, requiring {t} to reconstruct...\n");
var shares = sss.SplitSecret(originalSecret, n, t);

foreach (var share in shares)
{
    // In a real application, you'd store/transmit these securely.
    Console.WriteLine($"Share {share.X} (Serialized): {share}");
}
Console.WriteLine();

// Demo split again to show that we get different shares each time

Console.WriteLine($"Splitting the same secret again into {n} shares, requiring {t} to reconstruct...\n");
var newShares = sss.SplitSecret(originalSecret, n, t);
foreach (var share in newShares)
{
    Console.WriteLine($"New Share {share.X} (Serialized): {share}");
}
Console.WriteLine();

// --- Reconstruction ---
// Simulate having only a subset of shares

for (var i = 0; i < 10; i++)
{
    var availableShares = shares.OrderBy(x => Random.Shared.Next()).Take(t).ToList();
    // Make sure to take at least t shares, e.g. Take(random.Next(t, n + 1))

    Console.WriteLine($"Attempting reconstruction with {availableShares.Count} shares (IDs: {string.Join(", ", availableShares.Select(s => s.X))}):");

    try
    {
        var reconstructedSecret = sss.ReconstructSecretString(availableShares, t);
        Console.WriteLine($"Reconstructed Secret: {reconstructedSecret}");
        Console.WriteLine($"Success: {originalSecret == reconstructedSecret}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Reconstruction failed: {ex.Message}");
    }
    Console.WriteLine();
}

// --- Attempt reconstruction with too few shares ---
if (t > 1)
{
    var tooFewShares = shares.Take(t - 1).ToList();
    Console.WriteLine($"Attempting reconstruction with {tooFewShares.Count} shares (IDs: {string.Join(", ", tooFewShares.Select(s => s.X))}):");
    try
    {
        var reconstructedSecret = sss.ReconstructSecretString(tooFewShares, t);
        Console.WriteLine($"Reconstructed Secret (should be garbage or fail): {reconstructedSecret}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Reconstruction failed as expected: {ex.Message}");
    }
}