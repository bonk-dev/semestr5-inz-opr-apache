namespace Schiza.LogEngine.Tests;

internal sealed class LabeledFixture
{
    private const string CommentPrefix = "# ";

    private readonly Dictionary<string, string> _linesByLabel;

    private LabeledFixture(string fileName) => _linesByLabel = Load(fileName);

    public static LabeledFixture AccessLog { get; } = new("access-sample.txt");
    public static LabeledFixture ModSecAuditLog { get; } = new("modsec-audit-sample.txt");

    public IEnumerable<string> Labels => _linesByLabel.Keys;
    public string Line(string label) => _linesByLabel[label];

    private static Dictionary<string, string> Load(string fileName)
    {
        string path = Path.Combine(AppContext.BaseDirectory, "Fixtures", fileName);
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
