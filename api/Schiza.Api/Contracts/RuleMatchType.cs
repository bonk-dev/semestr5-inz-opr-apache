using System.Text.Json.Serialization;

namespace Schiza.Api.Contracts;

[JsonConverter(typeof(JsonStringEnumConverter<RuleMatchType>))]
public enum RuleMatchType
{
    /// <summary>Case-insensitive substring.</summary>
    Contains,

    /// <summary>Case-insensitive .NET regular expression.</summary>
    Regex,
}
