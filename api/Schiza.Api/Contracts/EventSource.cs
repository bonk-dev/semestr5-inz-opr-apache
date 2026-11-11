using System.Text.Json.Serialization;

namespace Schiza.Api.Contracts;

[JsonConverter(typeof(JsonStringEnumConverter<EventSource>))]
public enum EventSource
{
    /// <summary>Request read from access.log after it was handled.</summary>
    LogAnalysis,

    /// <summary>Request classified by mod_schiza before it was handled.</summary>
    BlockingModule,
}
