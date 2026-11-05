namespace Schiza.Shared.Requests;

/// <param name="Status">Final HTTP status ("%&gt;s").</param>
/// <param name="BytesSent">
/// Bytes sent on the wire ("%O"). Includes headers and, on a new TLS connection, the handshake.
/// </param>
/// <param name="BodyBytes">Response body size ("%B")</param>
/// <param name="Duration">Time taken to handle the request ("%D").</param>
public sealed record ResponseInfo(int Status, long BytesSent, long? BodyBytes, TimeSpan Duration);
