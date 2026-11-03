# sentinel-scanner: approved plan

Part of the Sentinel platform. The full cross-repo plan (API, dashboard, contracts) lives in
[sentinel-api/docs/PLAN.md](https://github.com/MundatiC/sentinel-api/blob/main/docs/PLAN.md).

## Tech choices

| Concern | Choice | Why |
| --- | --- | --- |
| CLI | Typer | The function signature *is* the CLI definition; `--help` is generated |
| HTTP | httpx (+ respx in tests) | Timeouts by default, easy to mock |
| TLS | stdlib `ssl` + `socket` | No dependency; easy to explain exactly what is checked |
| Models | pydantic v2 | Validates data sent to the API; mirrors the API's zod schemas |
| Output | rich (+ `--format json`) | Readable tables; machine-readable alternative |
| Reports | Jinja2 -> Markdown, fpdf2 -> PDF | fpdf2 is pure Python (no Cairo/Pango), so the image stays small |
| Quality | ruff, mypy (strict), pytest | |

## Defensive-only guardrails

1. `--i-own-this` is required for `web` scans (exit code 2 otherwise). `deps` and `logs` only read local files.
2. Read-only HTTP: GET and HEAD only, **no payloads are ever sent**.
3. Polite: delay between requests (default 0.5 s), sequential requests, timeouts, honest `User-Agent`.
4. The exposed-files check keeps only status, size and SHA-256 of what it finds, never file content (at most 1 KB is read).
5. The log analyzer only detects; it never replays or tests patterns.
6. http/https targets only; every finding records target and time (an audit trail).
7. The API key comes only from `SENTINEL_API_KEY`, never from a CLI argument (shell history / `ps`).

## Checks

| Check | Looks for |
| --- | --- |
| Headers | CSP, HSTS, X-Content-Type-Options, X-Frame-Options / frame-ancestors, Referrer-Policy, Permissions-Policy, `Server` / `X-Powered-By` leaks |
| Cookies | `Secure`, `HttpOnly`, `SameSite` on every `Set-Cookie` |
| TLS | Protocol version (< TLS 1.2), certificate expiry, hostname match, HTTP -> HTTPS redirect |
| Exposed files | Fixed list of sensitive paths, confirmed by a content signature |
| Dependencies | `requirements.txt` / `package-lock.json` / `poetry.lock` via the OSV `/v1/querybatch` API |

Log analyzer: nginx/apache combined logs and Linux `auth.log`; brute force (N failures per IP in a window) and
injection patterns (SQLi, XSS, path traversal). Post-mortem generator: Markdown and PDF from a YAML timeline or an incident
exported from the API.

## CLI

```
sentinel-scan web <url> --i-own-this [--checks headers,cookies,tls,files] [--format table|json] [--send]
sentinel-scan deps <path> [--send]
sentinel-scan logs <file> --type nginx|auth [--threshold 5 --window 60] [--send]
sentinel-scan postmortem (--timeline incident.yaml | --incident-id UUID) --out report.md [--pdf]
```

## Build steps

| # | Step | Commit |
| - | ---- | ------ |
| 1 | Scaffold, `--i-own-this` guard, HTTP client, models, tooling, CI | `chore: scaffold scanner CLI with ownership guard, tooling and CI` |
| 2 | Headers, cookies, TLS, exposed-files checks + `web` output | `feat(web): passive header, cookie, TLS and exposed-file checks` |
| 3 | Dependency check via OSV + `deps` command | `feat(deps): dependency vulnerability check via OSV batch API` |
| 4 | Log parsers + detectors + `logs` command + API client / `--send` | `feat(logs): brute-force and injection detection with API ingestion` |
| 5 | Post-mortem generator (MD/PDF), README, SECURITY.md | `feat(report): incident post-mortem generator; docs: README and responsible use` |
