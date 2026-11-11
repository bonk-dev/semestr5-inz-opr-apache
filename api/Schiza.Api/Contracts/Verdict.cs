using System.Text.Json.Serialization;

namespace Schiza.Api.Contracts;

[JsonConverter(typeof(JsonStringEnumConverter<Verdict>))]
public enum Verdict
{
    Safe,
    Unsafe,
}
