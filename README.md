# @pipeworx/statuspage

Service status / uptime MCP — "is X down right now?" answered from vendors' own
Atlassian Statuspage feeds. Keyless.

Atlassian Statuspage is a de-facto standard: hundreds of vendors expose the same
JSON contract at `https://<status-host>/api/v2/status.json`. This pack reads that
contract, so it closes a class of question rather than one vendor.

## Tools

- `statuspage_check(vendor | status_host, include_components?)` — current status for
  one vendor: overall indicator, the vendor's own status line, every degraded
  component, open incidents with the latest update text, and upcoming maintenance
  where published.
- `statuspage_incidents(vendor | status_host, unresolved_only?, limit?, include_all_updates?)`
  — incident history: title, lifecycle status, impact, start/resolve times,
  duration, affected components, latest update.
- `statuspage_list_vendors(category?, query?, include_elsewhere?)` — the vendors this
  pack can answer for, with each one's status host, so a name can be confirmed
  rather than guessed.
- `statuspage_multi_check(vendors[])` — up to 20 vendors in one call, returned as a
  compact up/down table plus a roll-up. Hosts are de-duplicated, concurrency capped
  at 5.

## Coverage

Coverage is **the curated vendor map plus any caller-supplied host.**

The curated map holds **123 vendors** across AI/model providers, cloud and hosting,
databases and observability, developer tools, payments and fintech, communications,
and business SaaS.

**Every host in the map was verified, not guessed.** 206 candidate hosts were probed
live; each survivor had to return a parseable Statuspage v2 payload on
`/api/v2/status.json`, `/api/v2/summary.json` *and* `/api/v2/incidents.json`.
Candidates that failed were dropped rather than shipped on a hunch — status
hostnames are genuinely unguessable (`status.anthropic.com` redirects to
`status.claude.com`; `status.cloudflare.com` does not resolve at all, the real host
is `www.cloudflarestatus.com`).

For anything outside the map, pass `status_host: "status.somevendor.com"`. Every
response says which of the two it used via the `source` field
(`curated_map` | `caller_supplied_host`).

### Vendors that publish status elsewhere

Roughly 43 well-known companies were probed and found to publish status in some
other format — AWS, Google Cloud, Azure, Slack, Stripe, GitLab, Heroku, PagerDuty,
Notion, Databricks and others. Asking for one of those returns
`reason: 'vendor_not_statuspage'` together with the URL a human should open, rather
than nothing. `statuspage_list_vendors({include_elsewhere: true})` lists them.

### Statuspage "lite" hosts

17 hosts in the map serve `status.json` / `summary.json` / `incidents.json` but omit
`/api/v2/incidents/unresolved.json` (OpenAI is one). The pack falls back to filtering
the incident feed for open incidents, and reports which path it used in
`incidents_source`.

## Result semantics

- **"All Systems Operational" is a positive result**, returned as `found: true`
  with `operational: true` and an empty `open_incidents` array.
- **A vendor with no incidents and a status page we could not read never look the
  same.** A fetch failure returns `found: false, reason: 'status_page_unreachable'`.
- An unrecognised vendor returns `found: false, reason: 'vendor_not_covered'` with
  near matches and a pointer to `statuspage_list_vendors` — never a guessed host,
  never a silently substituted vendor.

## Data source

Atlassian Statuspage v2 REST API, served by each vendor on its own status host:

- `/api/v2/status.json` — overall indicator + description
- `/api/v2/summary.json` — status + components + active incidents + maintenance
- `/api/v2/incidents.json`, `/api/v2/incidents/unresolved.json`
- `/api/v2/components.json`

No API key, no auth, no rate-limit handling in the pack.

## Quick Start

Add to your MCP client (Claude Desktop, Cursor, Windsurf, etc.):

```json
{
  "mcpServers": {
    "statuspage": {
      "url": "https://gateway.pipeworx.io/statuspage/mcp"
    }
  }
}
```

Or connect to the full Pipeworx gateway for access to all 1422+ data sources:

```json
{
  "mcpServers": {
    "pipeworx": {
      "url": "https://gateway.pipeworx.io/mcp"
    }
  }
}
```

## Using with ask_pipeworx

Instead of calling tools directly, you can ask questions in plain English:

```
ask_pipeworx({ question: "your question about Statuspage data" })
```

The gateway picks the right tool and fills the arguments automatically.

## More

- [All tools and guides](https://github.com/pipeworx-io/examples)
- [pipeworx.io](https://pipeworx.io)

## License

MIT
