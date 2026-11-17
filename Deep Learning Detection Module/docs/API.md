# API contract

For whoever builds the front end. The base URL is the backend itself; all paths below start with `/api`.

* **Same origin, cookie session.** The backend serves the front-end build from `wwwroot/` and the API from the
  same origin, so there is **no CORS**. During development, proxy `/api` to the backend (e.g. Vite:
  `server.proxy = { "/api": "http://localhost:5000" }`). The session is an `HttpOnly`, `SameSite=Strict` cookie:
  do not try to read or store a token; just call `fetch(..., { credentials: "same-origin" })`.
* **JSON**, property names **camelCase**, times are **UTC ISO-8601 with `Z`** (`2026-10-28T10:02:11.317Z`).
* `explanation` (detail endpoint only) is the detector's own document and keeps its **snake_case** names.
* Unauthenticated calls answer **401** (never a redirect). Unknown `/api/*` paths answer **404** with an empty body.
* **Everything the page displays about a request is attacker-controlled text** (URL, user agent, matched evidence).
  Render it as text. Never use `innerHTML` / `dangerouslySetInnerHTML` for it.

## Values

| Field | Values |
|---|---|
| `severity` | `low` · `medium` · `high` (`high` = attack signature / traversal; `medium` = malformed or score ≥ 2× threshold; `low` = just over threshold; a heuristic, not a probability) |
| `status` | `new` · `reviewed` · `false_positive` |
| `sort` (query) | `recent` (default) · `severity` · `count` |

## Endpoints

### `POST /api/auth/login`  (rate limited: 5 / minute / IP)
Request `{ "username": "admin", "password": "..." }` → `200 { "username": "admin" }` and the session cookie.
`400` missing fields · `401` wrong credentials · `429` too many attempts.

### `POST /api/auth/logout` → `204`
### `GET /api/auth/me` → `200 { "username": "admin" }` or `401` (use it on page load to restore the session)

### `GET /api/anomalies`
Query: `severity`, `status`, `ip`, `q` (substring of URL or summary, max 200 chars), `sort`, `fromUtc`, `toUtc`
(last-seen range), `page` (from 1), `pageSize` (1–100, default 25). `400 { "error": "..." }` for an unknown
severity / status / sort.

```json
{
  "total": 134, "page": 1, "pageSize": 25,
  "items": [{
    "id": 42, "firstSeenUtc": "2026-10-28T10:02:11.317Z", "lastSeenUtc": "2026-10-28T10:07:45.902Z",
    "count": 7, "ip": "198.51.100.23", "method": "GET",
    "url": "/search?q=%27+OR+1%3D1--", "severity": "high",
    "summary": "SQL injection: always-true condition in URL: ?q=' OR 1=1--",
    "score": 0.0119, "scoreRatio": 0.501, "status": "new"
  }]
}
```
`count` is how many identical requests (same IP + method + URL) were merged into the row. List items deliberately
do **not** contain the explanation; fetch the detail when a row is opened.

### `GET /api/anomalies/{id}` → `200` detail, or `404`
This is what the "Why was this flagged?" screen is built from (trimmed to 2 of 5 `top_features`; values are from a
real detector run):

```json
{
  "id": 42,
  "firstSeenUtc": "2026-10-28T10:02:11.317Z",
  "lastSeenUtc": "2026-10-28T10:07:45.902Z",
  "count": 7,
  "ip": "198.51.100.23",
  "method": "GET",
  "url": "http://localhost:8080/tienda1/publico/anadir.jsp?id=3'+OR+1%3D1--&nombre=Vino+Rioja&precio=100&cantidad=55&B1=A%F1adir+al+carrito",
  "userAgent": "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
  "severity": "high",
  "summary": "SQL injection: always-true condition in URL: r.jsp?id=3' OR 1=1--&nombre=Vi",
  "score": 0.0119,
  "threshold": 0.0237,
  "scoreRatio": 0.501,
  "status": "new",
  "reviewNote": null,
  "reviewedBy": null,
  "reviewedUtc": null,
  "explanation": {
    "anomaly_score": 0.0119,
    "threshold": 0.0237,
    "is_anomaly": true,
    "triggered_rules": [
      "suspicious_payload"
    ],
    "score_ratio": 0.5008,
    "severity": "high",
    "summary": "SQL injection: always-true condition in URL: r.jsp?id=3' OR 1=1--&nombre=Vi",
    "reasons": [
      {
        "rule": "suspicious_payload",
        "signature": "sql_tautology",
        "category": "sql_injection",
        "field": "url",
        "evidence": "r.jsp?id=3' OR 1=1--&nombre=Vi",
        "description": "SQL injection: always-true condition"
      }
    ],
    "top_features": [
      {
        "feature": "special_char_ratio",
        "label": "Share of special characters in URL",
        "input_value": 3.3232,
        "reconstructed_value": 3.0454,
        "reconstruction_error": 0.0772,
        "error_share": 0.4998,
        "raw_value": 0.1667,
        "typical_value": 0.0215,
        "typical_std": 0.0437,
        "z_score": 3.3232,
        "direction": "higher",
        "description": "Share of special characters in URL is 16.7%, typical is 2.1% ± 4.4% (+3.3σ)"
      },
      {
        "feature": "query_param_count",
        "label": "Number of query parameters",
        "input_value": 1.237,
        "reconstructed_value": 1.4147,
        "reconstruction_error": 0.0316,
        "error_share": 0.2046,
        "raw_value": 5,
        "typical_value": 1.1573,
        "typical_std": 3.1065,
        "z_score": 1.237,
        "direction": "higher",
        "description": "Number of query parameters is 5, typical is 1.16 ± 3.11 (+1.2σ); unusual in combination with the other features"
      }
    ]
  }
}
```

How to read `explanation`:

* **`reasons`** (hard evidence) is empty when only the statistical model flagged the request. Each entry:
  `signature` (machine name), `category` (group these in the UI: `sql_injection`, `xss`, `file_disclosure`,
  `command_injection`, `template_injection`, `encoding_abuse`, `scanner`, `path_traversal`, `malformed`, `novelty`),
  `field` (`url` · `body` · `user_agent`), `evidence` (the matching text, URL-decoded), `description` (a sentence).
* **`top_features`** (statistical evidence): the features the autoencoder reconstructed worst, sorted by
  `error_share` (fractions summing to ≤ 1). `description` is a ready-made sentence; `z_score` / `typical_value` /
  `raw_value` allow charts. `direction` is `higher` or `lower`. Categorical features have no `z_score`.
* **`score_ratio`** < 1 means a *rule* flagged it, not the model (show it as such).
* The sentence "unusual in combination with the other features" appears when a value is normal on its own but does
  not fit the other features; an autoencoder judges the whole request, not each number alone.
* Treat unknown extra properties as harmless: the detector's explanation format may grow.

### `PATCH /api/anomalies/{id}` → `204`, `404`, or `400`
Request `{ "status": "false_positive", "note": "monitoring probe" }`. `note` is optional (max 1000 chars; blank = cleared).
The reviewer name and time are taken from the session.

### `GET /api/stats`  (poll every ~10 s; there is no push channel)
```json
{
  "total": 134, "open": 91, "last24h": 58,
  "bySeverity": [{"severity": "high", "count": 40}, {"severity": "low", "count": 94}],
  "byStatus":   [{"status": "new", "count": 91}, {"status": "reviewed", "count": 43}],
  "hourly": [{"hour": "2026-10-28T09:00:00Z", "events": 12, "high": 4}],
  "topIps": [{"ip": "198.51.100.23", "events": 31}],
  "pipeline": {"linesRead": 120344, "unparseable": 31, "scored": 120313, "flagged": 58, "suppressed": 0,
               "dropped": 0, "errors": 0, "lastScoredUtc": "2026-10-28T10:07:45Z"},
  "detector": {"status": "ok", "modelLoaded": true, "threshold": 0.0237,
               "activeRules": ["malformed_request", "path_traversal", "suspicious_payload"], "closedWorld": false}
}
```
* `hourly` contains **only hours that have events**; fill the gaps with zeros to draw 24 bars. Hours are UTC.
* `bySeverity` / `byStatus` omit values with a count of 0.
* `detector` is `null` when the detector service is unreachable. Show that prominently: nothing is being scored.
* `pipeline.errors` counts batches dropped because scoring or storing failed; `dropped` counts log lines discarded
  because the queue was full; `suppressed` counts flagged requests not stored because their IP exceeded its hourly budget.
