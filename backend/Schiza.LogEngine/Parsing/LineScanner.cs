namespace Schiza.LogEngine.Parsing;

/// <summary>
/// Low-allocation reader for parsing space separated tokens
/// </summary>
internal ref struct LineScanner(ReadOnlySpan<char> line)
{
    private ReadOnlySpan<char> _rest = line;
    private bool _isFirstField = true;

    /// <summary>
    /// Indicates whether the entire line has been parsed already
    /// </summary>
    public readonly bool IsAtEnd => _rest.IsEmpty;

    /// <summary>
    /// Reads a space-separated value
    /// <returns>True if parsed a value, false otherwise</returns>
    /// </summary>
    public bool TryReadToken(out ReadOnlySpan<char> value)
    {
        value = default;
        if (!TryStartField())
        {
            return false;
        }

        int end = _rest.IndexOf(' ');
        value = end < 0 ? _rest : _rest[..end];
        _rest = _rest[value.Length..];
        return !value.IsEmpty;
    }

    /// <summary>
    /// Reads a value thats surrounded in a bracket ([...])
    /// <returns>True if parsed a value, false otherwise</returns>
    /// </summary>
    public bool TryReadBracketed(out ReadOnlySpan<char> value)
    {
        value = default;
        if (!TryStartField() || _rest.IsEmpty || _rest[0] != '[')
        {
            return false;
        }

        int end = _rest.IndexOf(']');
        if (end < 0)
        {
            return false;
        }

        value = _rest[1..end];
        _rest = _rest[(end + 1)..];
        return true;
    }

    /// <summary>
    /// Reads a quoted value while considering Apache escaping: \\ for backslashes and \" for quotes inside the quotes
    /// <returns>True if parsed a value, false otherwise</returns>
    /// </summary>
    public bool TryReadQuoted(out ReadOnlySpan<char> value)
    {
        value = default;
        if (!TryStartField() || _rest.IsEmpty || _rest[0] != '"')
        {
            return false;
        }

        ReadOnlySpan<char> body = _rest[1..];
        int position = 0;
        while (position < body.Length)
        {
            int next = body[position..].IndexOfAny('"', '\\');
            if (next < 0)
            {
                return false;
            }

            position += next;
            if (body[position] == '"')
            {
                value = body[..position];
                _rest = body[(position + 1)..];
                return true;
            }

            position += 2;
        }

        return false;
    }

    private bool TryStartField()
    {
        if (_isFirstField)
        {
            _isFirstField = false;
            return true;
        }

        if (_rest.IsEmpty || _rest[0] != ' ')
        {
            return false;
        }

        _rest = _rest[1..];
        return true;
    }
}
