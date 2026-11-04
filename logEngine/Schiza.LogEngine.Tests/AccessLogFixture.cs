namespace Schiza.LogEngine.Tests;

internal static class AccessLogFixture
{
    private const string CommentPrefix = "# ";

    private static readonly Dictionary<string, string> LinesByLabel = Load();

    public static IEnumerable<string> Labels => LinesByLabel.Keys;
    public static string Line(string label) => LinesByLabel[label];

    private static Dictionary<string, string> Load()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "Fixtures", "access-sample.txt");
        Dictionary<string, string> lines = [];
        string? previous = null;
        foreach (string line in File.ReadLines(path))
        {
            if (line.Length > 0 && !line.StartsWith(CommentPrefix, StringComparison.Ordinal))
            {
                lines.Add(previous![CommentPrefix.Length..], line);
            }

            previous = line;
        }

        return lines;
    }
}
