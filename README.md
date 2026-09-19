# LLMScan

Automated LLM penetration testing tool based on the OWASP LLM Top 10.

Point it at any LLM endpoint, local or cloud, and it fires attack payloads
across all 10 OWASP vulnerability categories, classifies the responses,
scores risk, and generates audience specific reports for pentesters,
managers, and executives.

**Fully offline capable.** Attack prompts are generated locally, so no
external LLM calls are needed to run a scan. It works out of the box against
Ollama, vLLM, LM Studio, OpenAI, Anthropic, and any OpenAI compatible API,
plus fully custom request and response formats for nonstandard targets.

---

## Table of contents

- [Quick start](#quick-start)
- [How a scan works](#how-a-scan-works)
- [Endpoint formats](#endpoint-formats)
- [Scan profiles](#scan-profiles)
- [CLI reference](#cli-reference)
- [Generating reports](#generating-reports)
- [API reference](#api-reference)
- [Environment variables](#environment-variables)
- [Project structure](#project-structure)
- [Optional extras](#optional-extras)
- [Running tests](#running-tests)
- [Development status](#development-status)

---

## Quick start

```powershell
# 1. Install engine dependencies
cd engine
uv sync --extra dev

# 2. Start the API server
uv run python -m uvicorn llmscan_engine.api.main:app --reload --port 8000

# 3. Start the dashboard in a separate terminal
cd dashboard
npm install
npm run dev
# opens on http://localhost:5173
```

Open the dashboard, enter your target endpoint URL and API key, pick a scan
profile, and click **Launch scan**. Findings, a live event feed, and
audience specific reports are all available from there.

### Testing a local Ollama model, fully offline

```powershell
cd engine
uv run llmscan scan \
  --target http://localhost:11434/v1/chat/completions \
  --key none \
  --model llama3 \
  --profile standard
```

`--model` matters here: OpenAI compatible local servers such as Ollama,
vLLM, and LM Studio reject requests that omit a model name.

> On Windows machines where Application Control policies block executable
> shims (AppLocker and similar), replace `uv run llmscan` with
> `uv run python -m llmscan_engine.cli.main` everywhere in this document.

---

## How a scan works

1. **Fingerprint.** Three benign probes are sent to the target to detect its
   provider (OpenAI compatible or Anthropic), rate limits, model name, and
   whether it appears to have a constraining system prompt.
2. **Dispatch.** Each enabled attack plugin generates its payloads (from
   built in YAML templates, optionally merged with Garak probes), and every
   payload is sent to the target with bounded concurrency and automatic
   retry on 429 or 503 responses.
3. **Classify.** Each response passes through up to four classifier layers:
   the plugin's own keyword classifier, a semantic similarity layer, Garak
   string detectors, and an optional LLM as judge layer. The layer that
   finds the most severe result wins.
4. **Score and store.** Findings are saved with a risk score from 0 to 10,
   where 10 is the most vulnerable. Low confidence, inconclusive results are
   not recorded as findings, they only show up in the live event count.
5. **Report.** Once a scan completes, generate a pentester, manager, or CXO
   report from the same findings, each with a different level of technical
   detail.

Nothing in this pipeline calls an external LLM to generate attacks. The only
network traffic is LLMScan talking directly to the target you configured.

---

## Endpoint formats

Most targets need no configuration beyond a URL, key, and model name. For
targets with a nonstandard request or response shape, pick a format:

| Format | Request shape | Use for |
|---|---|---|
| `openai` (default) | `{"messages": [...], "max_tokens": N, "model"?: ...}` | OpenAI, most cloud APIs |
| `ollama` | `{"messages": [...], "model"?: ...}` | Ollama, vLLM, LM Studio |
| `custom` | Your own JSON template | Any endpoint with a nonstandard request or response shape |

For `custom`, provide a request template with a `{prompt}` placeholder and a
dot notation path to the reply text in the response. The placeholder is
substituted with each attack payload after safe JSON escaping, so payloads
containing quotes or newlines cannot break your template.

Example, an internal endpoint that expects `{"input": "...", "session": "..."}`
and answers with `{"output": {"text": "..."}}`:

```powershell
uv run llmscan scan \
  --target http://internal-service:8080/chat \
  --key none \
  --endpoint-format custom \
  --request-template '{"input": "{prompt}", "session": "scan-01"}' \
  --response-path output.text
```

The same three fields (`endpoint_format`, `request_template`,
`response_path`) are also available as a dropdown on the dashboard's New
Scan form, and as fields on `POST /api/scans`.

---

## Scan profiles

| Profile | Plugins | Payloads per plugin | Garak |
|---|---|---|---|
| `quick` | LLM01 only | Up to 20 | Disabled |
| `standard` | All 10 categories | Up to 20 each | Used if installed |
| `full` | All 10 categories | Unlimited | Required |

Pass `--no-garak` on the CLI, or uncheck the toggle on the dashboard, to
force built in YAML templates only regardless of profile.

---

## CLI reference

All commands run from `engine/`.

### `scan`

```powershell
uv run llmscan scan \
  --target http://localhost:11434/v1/chat/completions \
  --key none \
  --profile quick
```

| Flag | Purpose |
|---|---|
| `--target` | Target LLM endpoint URL, required |
| `--key` | API key, or `none` for unauthenticated targets. Remembered in the OS keychain, so later runs against the same target can omit it |
| `--model` | Model name sent with every request |
| `--profile` | `quick`, `standard`, or `full` |
| `--endpoint-format` | `openai`, `ollama`, or `custom` |
| `--request-template` | Custom format only, a JSON body with a `{prompt}` placeholder |
| `--response-path` | Custom format only, dot notation path to the reply text |
| `--dry-run` | Log what would be sent without making any HTTP requests |
| `--no-garak` | Skip Garak probes even if the profile enables them |
| `--offline` | Refuse to run if `LLMSCAN_JUDGE_API_KEY` is set, since that layer needs network access |
| `--yes` | Skip the confirmation prompt before a scan expected to send more than 100 requests |
| `--json` | Print a single machine readable JSON object to stdout instead of a formatted table, for CI pipelines |

### `history`

```powershell
uv run llmscan history --limit 10
```

Lists past scans, newest first. Add `--json` for machine readable output.

### `plugins`

```powershell
uv run llmscan plugins list
uv run llmscan plugins update
```

`list` shows every registered attack plugin with its OWASP category and
severity weight. `update` reloads the plugin registry from disk, picking up
any new community plugins dropped into `plugins/`.

### `report`

See [Generating reports](#generating-reports).

---

## Generating reports

Once a scan reaches `status: complete`, generate an audience specific
report:

```powershell
uv run llmscan report --scan-id <scan-id> --audience pentester --format html
uv run llmscan report --scan-id <scan-id> --audience manager --format html
uv run llmscan report --scan-id <scan-id> --audience cxo --format pdf
```

`--audience` is one of `pentester`, `manager`, or `cxo`. `--format` is
`html`, always available, or `pdf`, which needs the optional `pdf` extra:

```powershell
uv sync --extra pdf
uv run playwright install chromium
```

The same thing is available through the API:
`POST /api/scans/{id}/report` with body `{"audience": "manager", "format": "html"}`.

Reports are written to `reports/output/{scan_id}/report_{audience}.{html,pdf}`
and are never committed to version control.

| Audience | What it shows |
|---|---|
| `pentester` | Full risk table, per finding sections grouped by OWASP category with the actual payload sent, the model's response, and reproduction details |
| `manager` | Risk heatmap across all 10 categories, a fix priority queue with SLA due dates |
| `cxo` | A risk score gauge, an impact narrative, and a compliance gap table mapped to SOC 2, ISO 27001, and the EU AI Act |

---

## API reference

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/scans` | Start a scan. Returns 202 immediately and runs in the background |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/scans/{id}` | Get scan details |
| `POST` | `/api/scans/{id}/cancel` | Cancel a running scan |
| `GET` | `/api/scans/{id}/findings` | List findings, filterable by `owasp_id`, `failure_mode`, `min_score` |
| `GET` | `/api/scans/{id}/findings/{finding_id}/evidence` | Get the real prompt and response text behind a finding |
| `GET` | `/api/plugins` | List registered attack plugins |
| `POST` | `/api/plugins/update` | Reload the plugin registry |
| `POST` | `/api/scans/{id}/report` | Generate a pentester, manager, or cxo report, HTML or PDF |
| `WS` | `/ws/scan/{id}` | Live event stream for a running scan |

---

## Environment variables

Copy `.env.example` to `.env` and fill in what you need:

```env
LLMSCAN_TARGET_URL=http://localhost:11434/v1/chat/completions
LLMSCAN_API_KEY=ollama
LLMSCAN_MAX_CONCURRENCY=3
LLMSCAN_SCAN_PROFILE=standard

# Optional, enables the LLM as judge classifier layer
# LLMSCAN_JUDGE_API_KEY=sk-...
# LLMSCAN_JUDGE_MODEL=gpt-4o-mini
```

| Variable | Meaning | Required |
|---|---|---|
| `LLMSCAN_TARGET_URL` | Endpoint of the LLM you are testing | Yes |
| `LLMSCAN_API_KEY` | Auth key for the target, use `none` for unauthenticated endpoints | Yes |
| `LLMSCAN_MAX_CONCURRENCY` | Parallel requests, default 3, max 10 | No |
| `LLMSCAN_SCAN_PROFILE` | Default profile if none is passed explicitly | No |
| `LLMSCAN_JUDGE_API_KEY` | Auth key for a separate LLM used only to classify results, not to attack | No |
| `LLMSCAN_JUDGE_MODEL` | Model name for the judge, for example `gpt-4o-mini` | No |

`LLMSCAN_API_KEY` and `LLMSCAN_JUDGE_API_KEY` are two different keys for two
different purposes. The first authenticates to the LLM being attacked. The
second, entirely optional, authenticates to a separate LLM used only to
help classify whether a response counts as a compliance or a refusal.
Setting the judge key means the tool is no longer fully offline, since that
one classifier layer will make an external call. Everything else in the
pipeline, including attack generation, always stays local.

---

## Project structure

```
llmscan/
  engine/                     Python backend, FastAPI and the attack engine
    src/llmscan_engine/
      api/                    FastAPI routers, WebSocket feed, orchestrator
      core/                   Dispatcher, fingerprinter, classifier
      plugins/                12 built in OWASP attack plugins, LLM01 to LLM10
      profiles/               Scan profile YAML files, quick/standard/full
      db/                     SQLModel models and Alembic migrations
      cli/                    Typer CLI, scan/history/plugins/report
      reports/                Jinja2 report generator, pentester/manager/cxo
  dashboard/                  React 18, Vite, TypeScript frontend
    src/
      pages/                  ScanSetup, ScanLive, FindingExplorer, ScanHistory
      components/             RiskRadar, PluginGrid, FindingDetail, AudienceToggle
      hooks/                  useScanFeed, the WebSocket hook
      context/                AppContext, React Context plus useReducer
      lib/                    api.ts, the typed fetch wrapper
  plugins/                    Community plugin drop folder
  tests/                      pytest test suite
  reports/output/             Generated scan evidence and reports, gitignored
```

---

## Optional extras

Everything below is optional. LLMScan runs fully offline without any of it.

### Garak probe library

[Garak](https://github.com/NVIDIA/garak) adds a large additional set of
attack probes, entirely local, no API key required.

```powershell
cd engine
uv sync --extra dev --extra garak
```

### PDF report export

Requires headless Chromium via Playwright.

```powershell
cd engine
uv sync --extra pdf
uv run playwright install chromium
```

### Semantic similarity classifier layer

Adds a `sentence-transformers` based similarity check as classifier layer 2.
The model is cached locally after the first run.

```powershell
cd engine
uv sync --extra ml
```

---

## Running tests

```powershell
cd engine
uv run python -m pytest -v
```

Always run tests from `engine/` through `uv run`. A bare `pytest` picks up
whatever Python is on your system PATH, which will not have the project or
its dependencies installed.

---

## Development status

| Phase | Description | Status |
|---|---|---|
| 01 | Monorepo scaffold, CI/CD | Done |
| 02 | SQLite data models | Done |
| 03 | Target connector and fingerprinter | Done |
| 04 | Plugin SDK and base interface | Done |
| 05 | Async dispatcher and evidence logger | Done |
| 06 | LLM01 and LLM02 attack plugins | Done |
| 07 | LLM03, LLM04, LLM05 plugins | Done |
| 08 | LLM06 through LLM10 plugins | Done |
| 09 | Response classifier, 4 layers | Done |
| 10 | FastAPI server and WebSocket | Done |
| 11 | React dashboard | Done |
| 12 | Report generator, 3 audiences | Done |
| 13 | CLI polish, scan profiles, safety controls | Done |
| 14 | Plugin registry and community extensibility |  |
