using Microsoft.AspNetCore.Mvc;

using Schiza.Api.Contracts;
using Schiza.Api.Mocks;

namespace Schiza.Api.Controllers;

[ApiController]
[Route("events")]
public sealed class EventsController(IEventStore events) : ControllerBase
{
    /// <summary>
    /// Lists classified events with their classification, newest first.
    /// </summary>
    /// <remarks>
    /// Only unsafe requests are stored, safe requests are not kept (client addresses are personal data).
    /// </remarks>
    [HttpGet]
    [ProducesResponseType<EventPage>(StatusCodes.Status200OK)]
    [ProducesResponseType<ValidationProblemDetails>(StatusCodes.Status400BadRequest)]
    public EventPage Query([FromQuery] EventQuery query) => events.Query(query);

    [HttpGet("{id:int}")]
    [ProducesResponseType<SecurityEvent>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public ActionResult<SecurityEvent> Get(int id) => events.Get(id) is { } securityEvent ? securityEvent : NotFound();
}
