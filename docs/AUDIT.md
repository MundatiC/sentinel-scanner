# Code audit (ponytail method)

Audited the whole repo like the developer who inherited it: correct, safe, holds under load, tested, fast, lean.
Assumed load: one person running the CLI on their own site, project folder or log file; log files can be large (gigabytes).
Every finding was reproduced or measured before it was fixed.

| #   | Finding                                                                               | Case                                                                                                                                                          | Status                                                                                                                                                                                      |
| --- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Must fix.** `logs` kept every log line in memory, although the docs said it streams | A 600,000-line, 67 MB access log used **307 MB** to find 2 detections; memory grows with the file, so a multi-gigabyte production log would run out of memory | Fixed: only failed logins and attack-signature matches are kept while streaming. Same detections, **72 MB** (the interpreter's baseline). Tests prove the filter does not change any result |
| 2   | **Nice to have.** `ParsedCookie.attributes` was never read                            | grep: written nowhere, read nowhere                                                                                                                           | Removed                                                                                                                                                                                     |

Checked and **not** findings: vulture reports Typer commands (`main`, `web`, `logs`), pydantic `model_config`, `LogType.apache` (a CLI value) and
the `FPDF.footer` hook as unused; they are all used by their frameworks.

Known limits kept on purpose: only exactly pinned dependency versions can be checked; heuristic log signatures can miss obfuscated payloads; PDF output is Latin-1;
the OSV client has only been tested against fixtures in OSV's documented format (the sandbox could not reach `api.osv.dev`).

Not checked: live OSV behaviour; throughput beyond ~600,000 lines (about 18 s, dominated by the signature matching).
