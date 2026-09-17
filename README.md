# LLMScan

Automated LLM penetration testing tool based on the OWASP LLM Top 10.

Point it at any LLM endpoint (local or cloud), and it fires attack payloads across all 10 OWASP vulnerability categories, classifies responses, scores risk, and delivers audience-specific reports.

**Fully offline-capable.** Attack prompts are generated locally — no external LLM calls needed. Supports Ollama, vLLM, LM Studio, OpenAI, Anthropic, and any OpenAI-compatible API.

---

## Quick start

```powershell
# 1. Install engine
cd engine
uv sync --extra dev

# 2. Start the API server
uv run python -m uvicorn llmscan_engine.api.main:app --reload --port 8000

# 3. Start the dashboard (separate terminal)
cd dashboard
npm install
npm run dev
# → http://localhost:5173
```

Open the dashboard, enter your target endpoint URL and API key, pick a scan profile, and click **Launch scan**.

---

## Testing a local Ollama model (fully offline)

```powershell
cd engine
uv run llmscan scan \
  --target http://localhost:11434/v1/chat/completions \
  --key ollama \
  --profile standard
```

---

## Scan profiles

| Profile | Plugins | Payloads | Garak |
|---|---|---|---|
| `quick` | LLM01 only | 20 | No |
| `standard` | All 10 | 20 each | If installed |
| `full` | All 10 | Unlimited | Required |

---

## Generating reports

Once a scan has `status: complete`, generate an audience-specific report
via the CLI:

```powershell
cd engine
uv run python -m llmscan_engine.cli.main report \
  --scan-id <scan-id> --audience pentester --format html

uv run python -m llmscan_engine.cli.main report \
  --scan-id <scan-id> --audience cxo --format pdf
```

`--audience` is one of `pentester` / `manager` / `cxo`; `--format` is
`html` (always available) or `pdf` (requires the optional `pdf` extra):

```powershell
uv sync --extra pdf
uv run playwright install chromium
```

Or via the API: `POST /api/scans/{id}/report` with
`{"audience": "manager", "format": "html"}`. Reports are written to
`reports/output/{scan_id}/report_{audience}.{html,pdf}`.

---

## API reference

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/scans` | Start a scan (returns 202, runs in background) |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/scans/{id}` | Get scan details |
| `GET` | `/api/scans/{id}/findings` | List findings (filter: `owasp_id`, `failure_mode`, `min_score`) |
| `GET` | `/api/plugins` | List registered attack plugins |
| `POST` | `/api/plugins/update` | Reload plugin registry |
| `POST` | `/api/scans/{id}/report` | Generate a pentester/manager/cxo report (HTML or PDF) |
| `WS` | `/ws/scan/{id}` | Live event stream for a running scan |

---

## Environment variables

Copy `.env.example` to `.env` and fill in:

```env
LLMSCAN_TARGET_URL=http://localhost:11434/v1/chat/completions
LLMSCAN_API_KEY=ollama
LLMSCAN_MAX_CONCURRENCY=3
LLMSCAN_SCAN_PROFILE=standard

# Optional — enables LLM-as-judge classifier (Layer 4)
# LLMSCAN_JUDGE_API_KEY=sk-...
# LLMSCAN_JUDGE_MODEL=gpt-4o-mini
```

---

## Project structure

```
llmscan/
├── engine/                    Python backend (FastAPI + attack engine)
│   └── src/llmscan_engine/
│       ├── api/               FastAPI routers, WebSocket feed, orchestrator
│       ├── core/              Dispatcher, fingerprinter, classifier
│       ├── plugins/           12 built-in OWASP attack plugins (LLM01–LLM10)
│       ├── profiles/          Scan profile YAML files (quick/standard/full)
│       ├── db/                SQLModel models + Alembic migrations
│       ├── cli/               Typer CLI (`llmscan report ...`)
│       └── reports/           Jinja2 report generator (pentester/manager/cxo)
├── dashboard/                 React 18 + Vite + TypeScript frontend
│   └── src/
│       ├── pages/             ScanSetup, ScanLive, FindingExplorer, ScanHistory
│       ├── components/        RiskRadar, PluginGrid, FindingDetail, AudienceToggle
│       ├── hooks/             useScanFeed (WebSocket)
│       ├── context/           AppContext (React Context + useReducer)
│       └── lib/               api.ts (fetch wrapper)
├── plugins/                   Community plugin drop folder
├── tests/                     pytest test suite (336+ tests)
└── reports/output/            Generated scan evidence + reports
```

---

## Optional: Garak probe library

[Garak](https://github.com/NVIDIA/garak) adds hundreds of additional attack probes locally — no API key required.

```powershell
cd engine
uv sync --extra dev --extra garak
```

---

## Development status

| Phase | Description | Status |
|---|---|---|
| 01 | Monorepo scaffold, CI/CD | ✅ |
| 02 | SQLite data models | ✅ |
| 03 | Target connector & fingerprinter | ✅ |
| 04 | Plugin SDK & base interface | ✅ |
| 05 | Async dispatcher & evidence logger | ✅ |
| 06 | LLM01 + LLM02 attack plugins | ✅ |
| 07 | LLM03 + LLM04 + LLM05 plugins | ✅ |
| 08 | LLM06–LLM10 plugins | ✅ |
| 09 | Response classifier (4-layer) | ✅ |
| 10 | FastAPI server + WebSocket | ✅ |
| 11 | React dashboard | ✅ |
| 12 | Report generator (3 audiences) | ✅ |
| 13 | CLI polish + scan profiles | ⬜ |
| 14 | Plugin registry + extensibility | ⬜ |

---

## Running tests

```powershell
cd engine
uv run python -m pytest -v
```

Always run from `engine/` through `uv run` — bare `pytest` uses the system
Python, which does not have the project installed.
