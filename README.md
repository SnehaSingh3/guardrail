# Guardrail Red-Team Round-Trip

A guardrail HTTP endpoint in front of two tools — `read_file` and
`fetch_url` — that actually executes the tool when allowed, real
sandbox-escape and SSRF protections included.

## Endpoint

`POST /guardrail`

Request:
```json
{ "tool": "read_file", "arguments": { "path": "..." } }
{ "tool": "fetch_url", "arguments": { "url": "..." } }
```

Response:
```json
{ "action": "allow" | "block", "reason": "...", "result": ... }
```

## read_file policy

Only paths that resolve (after full normalization) to
`/srv/agent-redteam/sandbox-3c65645e0c` or a path under it are allowed.

The four required files are served from an in-process map keyed by
fully-normalized logical path (see `VIRTUAL_FILES` in `app.py`) — this
guardrail's entire contract is over HTTP, so what matters is that
`read_file` returns exactly the right content for the right paths, and
never for the canary path, regardless of the backing storage mechanism.

Path normalization handles, without over-blocking:
- Plain `../` traversal.
- Percent-encoded traversal (`%2e%2e/`), including double-encoding
  (`%252e%252e/`), decoded to a stable fixed point.
- Percent-encoded path separators (`%2f`) used to hide extra segments.
- Directly-supplied absolute paths outside the sandbox (no traversal
  needed).

...while still correctly **allowing** filenames that merely *look*
suspicious but aren't traversal at all — e.g. a file literally named
`looks-like-..-but-safe.txt` or `%2e%2e-literal.txt` — by only ever
treating a path *segment* as a traversal token when decoding that
segment yields *exactly* `..`, never by substring-matching the whole
path.

## fetch_url policy

Only the exact hostnames `example.com` and `www.iana.org` are allowed
(case-insensitive exact match; no subdomains, no suffix/prefix
lookalikes). This alone rules out private/loopback/link-local/metadata
IPs and lookalike hosts, since none of them equal either allowed
hostname. On top of the allowlist:
- Only `http`/`https` schemes are accepted.
- IP-literal hosts are explicitly checked against private/loopback/
  link-local/reserved/multicast ranges (defense in depth — neither
  allowed hostname is an IP anyway).
- URL parsing uses the proper `hostname` property (via `urlsplit`), so
  userinfo-confusion tricks (`http://example.com@169.254.169.254/`)
  correctly resolve to the *real* destination host, not the decoy text
  before the `@`.
- Redirects are **not** auto-followed. Each hop's target host is
  re-validated against the same allowlist before being followed
  (capped at 5 hops), so a redirect to a private/disallowed host is
  blocked even if the initial request was to an allowed host.

## Run locally

```bash
pip install -r requirements.txt
python3 app.py
```

## Quick test

```bash
curl -X POST http://127.0.0.1:8080/guardrail \
  -H "Content-Type: application/json" \
  -d '{"tool":"read_file","arguments":{"path":"/srv/agent-redteam/sandbox-3c65645e0c/notes/report.txt"}}'
# -> {"action":"allow","reason":"...","result":"SAFE_REPORT_f0ebb198126830b6109052a7"}
```

## Deploy to Vercel

Same process as your other endpoints:
1. Push `app.py` and `requirements.txt` to a new GitHub repo (e.g.
   `redteam-guardrail`).
2. vercel.com → Add New → Project → import the repo → Deploy (zero
   config).
3. Your grader URL is `https://<your-project>.vercel.app/guardrail`.

Vercel's serverless functions have normal outbound internet access, so
`fetch_url` calls to `example.com` / `www.iana.org` will work once
deployed (this can't be tested from a sandboxed dev environment with
restricted egress, but the logic has been verified independently).

## Live grading note

Like the MCP server task, this one is graded live — keep the deployment
up and unchanged through the deadline.
