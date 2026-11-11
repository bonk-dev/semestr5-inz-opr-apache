using Microsoft.AspNetCore.Mvc;

using Schiza.Api.Contracts;
using Schiza.Api.Mocks;

namespace Schiza.Api.Controllers;

[ApiController]
[Route("rules")]
public sealed class RulesController(IRuleStore rules) : ControllerBase
{
    /// <summary>
    /// Lists all static rules, active and inactive.
    /// </summary>
    [HttpGet]
    public IReadOnlyList<StaticRule> GetAll() => rules.GetAll();

    [HttpGet("{id:int}")]
    [ProducesResponseType<StaticRule>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public ActionResult<StaticRule> Get(int id) => rules.Get(id) is { } rule ? rule : NotFound();

    /// <summary>
    /// Adds a static rule. A regex pattern is validated before it is stored.
    /// </summary>
    [HttpPost]
    [ProducesResponseType<StaticRule>(StatusCodes.Status201Created)]
    [ProducesResponseType<ValidationProblemDetails>(StatusCodes.Status400BadRequest)]
    public ActionResult<StaticRule> Create(CreateRuleRequest request)
    {
        if (!RuleMatcher.TryValidatePattern(request.MatchType, request.Pattern, out string? error))
        {
            ModelState.AddModelError(nameof(request.Pattern), $"Invalid regular expression: {error}");
            return ValidationProblem(ModelState);
        }

        StaticRule rule = rules.Add(request);
        return CreatedAtAction(nameof(Get), new { id = rule.Id }, rule);
    }

    /// <summary>
    /// Starts evaluating the rule. Activating an active rule does nothing.
    /// </summary>
    [HttpPost("{id:int}/activate")]
    [ProducesResponseType<StaticRule>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public ActionResult<StaticRule> Activate(int id) => rules.SetActive(id, true) is { } rule ? rule : NotFound();

    /// <summary>
    /// Stops evaluating the rule but keeps it. Deactivating an inactive rule does nothing.
    /// </summary>
    [HttpPost("{id:int}/deactivate")]
    [ProducesResponseType<StaticRule>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public ActionResult<StaticRule> Deactivate(int id) => rules.SetActive(id, false) is { } rule ? rule : NotFound();

    [HttpDelete("{id:int}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public IActionResult Delete(int id) => rules.Remove(id) ? NoContent() : NotFound();
}
