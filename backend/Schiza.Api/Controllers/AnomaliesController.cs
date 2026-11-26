using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using Schiza.Application;
using Schiza.Domain;

namespace Schiza.Api.Controllers;

[ApiController]
[Authorize(Policy = "Admin")]
[Route("api/anomalies")]
public sealed class AnomaliesController(FlaggedEventQueries queries) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 25, [FromQuery] string? severity = null, CancellationToken cancellationToken = default)
    {
        if (page < 1 || pageSize is < 1 or > 100) return BadRequest(new { error = "Nieprawidłowa paginacja" });
        (IReadOnlyList<FlaggedEvent> items, int total) = await queries.ListAsync(page, pageSize, severity, cancellationToken);
        return Ok(new { total, page, pageSize, items });
    }

    [HttpGet("{id:long}")]
    public async Task<IActionResult> Detail(long id, CancellationToken cancellationToken)
    {
        FlaggedEvent? item = await queries.GetAsync(id, cancellationToken);
        return item is null ? NotFound() : Ok(item);
    }
}
