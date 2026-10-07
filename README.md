<p align="center">
  <img src="assets/logo.png" alt="MCP Sentry logo" width="420">
</p>

# MCP Sentry

Audit MCP tool definitions, recorded tool calls and integration permissions, offline.

MCP servers describe their tools in text that a model reads. That text can change after you approved it (a "rug pull"), can hide instructions in invisible characters, and can ask the model to leak credentials. MCP Sentry fingerprints tool definitions, compares them with what you approved, flags instruction-shaped and hidden text, and decides ALLOW or BLOCK for recorded calls against a policy you wrote.

It reads files. It does not run servers, sit between a client and a server, or sandbox anything: its decisions tell a gateway or a person what to block. It uses only the Python standard library and makes no network requests.

## Install

Requires Python 3.10 or newer.

```bash
pip install git+https://github.com/seun-john/mcp-sentry.git
```

## 1. Approve a tool list

Export the `tools/list` result from your MCP client or server as `{"tools": [...]}`, then:

```bash
mcp-sentry baseline tools.json -o approved.json
```

Read the tool descriptions yourself, then keep the `baseline` object from `approved.json`. Each fingerprint is a SHA-256 of the whole definition, schema included, so any edit to wording or parameters changes it.

## 2. Scan

```bash
mcp-sentry scan scan.json -o report.json --html report.html --strict
```

```json
{
  "tools": [{"name": "read_file", "description": "Reads a file.", "inputSchema": {}}],
  "baseline": {"read_file": "<fingerprint from step 1>"},
  "policy": {"read_file": {"allow": true, "argument_values": {"path": ["notes.txt"]},
                           "required_arguments": ["path"], "side_effect": false}},
  "calls": [{"tool": "read_file", "arguments": {"path": "notes.txt"}, "result": "..."}]
}
```

| Status | Meaning |
| --- | --- |
| `UNAPPROVED` | No approved fingerprint for this tool. |
| `CHANGED` | The definition differs from the approved fingerprint. |
| `MISSING` | An approved tool is no longer offered. |
| `SUSPICIOUS` | Text in the description or schema looks like an instruction to the model ("ignore previous instructions", "do not tell the user", "read ~/.ssh/id_rsa", `<IMPORTANT>`, "send the API key"). |
| `HIDDEN_TEXT` | Zero-width, bidirectional-control or Unicode tag characters, which can hide instructions from a human reader. |

Every string in the definition is scanned, including nested schema descriptions, and the finding says where it was found.

### Call decisions

Each recorded call gets `ALLOW` or `BLOCK` with reasons. Everything is denied unless a rule allows it:

- the tool must be approved and unchanged;
- the policy must contain `"allow": true` for it;
- every argument value must be listed in `argument_values` (there is no implicit trust of paths or URLs);
- `required_arguments` must be present;
- if `"side_effect": true`, the call needs an `approval_id`. **That reference is not authenticated here**; it only shows that a gateway claims a person approved;
- a result containing instruction-shaped or hidden text blocks the call. The result is returned with emails, phone numbers, keys and similar values redacted.

## 3. Map integration permissions

```bash
mcp-sentry access integrations.json -o access.json
```

```json
{"integrations": [{"id": "mail", "requested_use": "summarise my inbox",
                   "permissions": [{"resource": "*", "actions": ["read", "send"], "destinations": []}]}]}
```

Declared permissions become plain-language capabilities. Broad resources (`*`, `all`), high-impact actions (`delete`, `send`, `publish`, `execute`, `admin`) and outbound capabilities with no destination are flagged. You must map real OAuth scopes onto the seven actions yourself; MCP Sentry does not read provider scopes and does not contact any account.

## Options and exit codes

All commands take `-o report.json`, `--html report.html` and `--strict`. Exit codes: 0 the audit completed, 1 `--strict` and something was flagged, 2 unusable input. A completed audit with findings exits 0 unless you pass `--strict`, so use `--strict` in CI.

## Limits

- Heuristics catch common poisoning phrases, not every paraphrase. A clean scan is not proof of safety; the fingerprint comparison is the strong control.
- Fingerprints prove a definition is unchanged, not that it was safe when you approved it.
- Approval references are recorded, not verified.
- No protocol proxy, process isolation or network control is provided.

## Develop

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest -q
```

MIT licence.
