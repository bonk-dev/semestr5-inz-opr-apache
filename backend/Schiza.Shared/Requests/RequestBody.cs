namespace Schiza.Shared.Requests;

public sealed record RequestBody(
    string? ContentType,
    // for multipart/form-data modsecurity logs urlencoded fields without files
    string Content);
