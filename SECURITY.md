# Security Policy and Responsible Use

## Responsible use (read this first)

`sentinel-scanner` is a **defensive** tool. Use it only on systems **you own or have explicit, written permission
to test**. Scanning other people's systems without permission may be illegal where you live.

The tool is built so that misuse is hard, not just discouraged:

| Guardrail | How it is enforced |
| --- | --- |
| Explicit ownership confirmation | `web` refuses to run without `--i-own-this` (exit code 2). The check runs before the target is even parsed, and a test proves nothing is requested without it. |
| Read-only | The HTTP client only allows `GET` and `HEAD`. No code path can send a payload, form, credential or exploit string. |
| Polite | Requests are sequential, 0.5 s apart by default, with timeouts and an honest `User-Agent` that says it is an authorised self-assessment. |
| No secret harvesting | The exposed-files check reads at most 1 KB, then keeps only the status, size and a SHA-256 fingerprint, never content. Cookie values are discarded while parsing. |
| Fixed scope | A short fixed list of well-known paths. No wordlists, crawling, brute forcing, or fuzzing. |
| Detection only | The log analyzer matches patterns in log text. It never replays requests or tests payloads. |
| Limited targets | `http`/`https` only; credentials in the target URL are refused. |
| Secrets stay out of shells | The API key comes only from `SENTINEL_API_KEY` (never a command-line flag), and is never printed or logged. |
| No clear-text keys | `--send` refuses plain `http://` API URLs except for loopback/private networks. |

There is **no exploit code, attack tooling or credential harvesting** in this project, and contributions adding any will not be accepted.

## Reporting a vulnerability in the scanner

Please report privately via GitHub: **Security → Report a vulnerability**
(<https://github.com/MundatiC/sentinel-scanner/security/advisories/new>) rather than opening a public issue.
You will get an acknowledgement within 5 working days. Only the latest commit on `main` is supported.

Examples that are in scope: a way to make the scanner send a non-GET/HEAD request or a payload, bypass `--i-own-this`,
leak the API key or a scanned secret into output, make it write outside the requested output path, or execute code
through a crafted input file (lockfile, YAML timeline, log line).

## Handling untrusted input

The scanner reads data that an attacker may control, so it treats all of it as hostile:

- **Target responses:** headers are truncated before being kept; terminal output is rendered as plain text, so a malicious
  `Server:` header cannot inject formatting or escape sequences.
- **Log files:** parsed strictly and line by line, with line-length limits; IPs are validated; unparsable lines are skipped.
- **YAML:** `yaml.safe_load` only, with a 1 MB size limit; unknown keys are rejected.
- **Lockfiles:** parsed with the standard `json`/`tomllib` modules with a 10 MB limit.
- **OSV responses:** vulnerability ids are validated before they are used in a URL.
- **Reports:** Markdown output escapes HTML and table characters from untrusted text; the PDF uses built-in fonts only.

## Privacy

`deps` sends package **names and versions** (nothing else) to `api.osv.dev`. `--send` sends results to **your own**
Sentinel API only. `logs --send` includes the request path of injection attempts, so do not use it on logs whose URLs contain secrets.
Nothing is sent anywhere unless you pass `--send` (or run `deps`, which queries OSV by design).

## Known limitations

- Heuristic log signatures can miss obfuscated payloads and rarely flag harmless requests.
- The TLS check inspects the handshake (certificate, protocol, cipher). It is not a full cipher-suite audit like `testssl.sh`.
- PDF output is Latin-1 only; use the Markdown report for other scripts.
- Only exactly pinned dependency versions can be checked.
