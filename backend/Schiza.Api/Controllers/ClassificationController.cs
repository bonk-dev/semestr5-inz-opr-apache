using System.Text.Json;

using Microsoft.AspNetCore.Mvc;

using Schiza.Application;
using Schiza.Application.Legacy;
using Schiza.Shared.Requests;

namespace Schiza.Api.Controllers;

[ApiController]
[Route("classify")]
public sealed class ClassificationController(IRequestClassifier classifier, IFlaggedEventRepository events) : ControllerBase
{
    /// <summary>
    /// Score of the result, so mod_schiza can log it without parsing JSON.
    /// </summary>
    public const string ScoreHeader = "Schiza-Score";

    private static readonly TimeSpan SlowDelay = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Classifies one request. Unsafe requests are stored as events.
    /// </summary>
    /// <remarks>
    /// The status code is the verdict, the contract used by mod_schiza: 200 for safe, 403 for unsafe.
    /// Any other status makes the module let the request through (fail-open).
    /// Mock only: paths starting with /__mock/slow or /__mock/error simulate a slow or failing backend.
    /// </remarks>
    [HttpPost]
    [ProducesResponseType<ClassificationResult>(StatusCodes.Status200OK)]
    [ProducesResponseType<ClassificationResult>(StatusCodes.Status403Forbidden)]
    [ProducesResponseType<ValidationProblemDetails>(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Classify(ApacheRequest request, CancellationToken cancellationToken)
    {
        string? path = request.RequestLine.Path;
        if (path?.StartsWith("/__mock/slow", StringComparison.Ordinal) == true)
        {
            await Task.Delay(SlowDelay, cancellationToken);
        }
        else if (path?.StartsWith("/__mock/error", StringComparison.Ordinal) == true)
        {
            return StatusCode(StatusCodes.Status500InternalServerError);
        }

        ClassificationResult result = await classifier.ClassifyAsync(request, cancellationToken);
        if (result.Verdict == Verdict.Unsafe)
        {
            string rawRequest = JsonSerializer.Serialize(request, JsonSerializerOptions.Web);
            await events.AddIfNewAsync(request, rawRequest, result, EventSource.BlockingModule, cancellationToken);
        }

        Response.Headers[ScoreHeader] = result.Score.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture);
        return StatusCode(result.Verdict == Verdict.Unsafe ? StatusCodes.Status403Forbidden : StatusCodes.Status200OK, result);
    }
}
