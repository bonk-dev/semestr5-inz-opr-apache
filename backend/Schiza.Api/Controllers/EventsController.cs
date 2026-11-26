using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Schiza.Application.Legacy;
using Schiza.Application;

namespace Schiza.Api.Controllers;

[ApiController]
[Authorize(Roles = "Admin")]
[Route("events")]
public sealed class EventsController(FlaggedEventQueries events) : ControllerBase
{
    /// <summary>
    /// Lists classified events with their classification, newest first.
    /// </summary>
    /// <remarks>
    /// Only unsafe requests are stored, safe requests are not kept (client addresses are personal data).
    /// </remarks>
    [HttpGet]
    [ProducesResponseType<FlaggedEventPage>(StatusCodes.Status200OK)]
    [ProducesResponseType<ValidationProblemDetails>(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<FlaggedEventPage>> Query([FromQuery] EventQuery query, CancellationToken cancellationToken)
    {
        (IReadOnlyList<Schiza.Domain.FlaggedEvent> items, int total) = await events.ListAsync(query, cancellationToken);
        return Ok(new FlaggedEventPage(items, total));
    }

    [HttpGet("{id:long}")]
    [ProducesResponseType<Schiza.Domain.FlaggedEvent>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<Schiza.Domain.FlaggedEvent>> Get(long id, CancellationToken cancellationToken) => await events.GetAsync(id, cancellationToken) is { } securityEvent ? securityEvent : NotFound();
}
