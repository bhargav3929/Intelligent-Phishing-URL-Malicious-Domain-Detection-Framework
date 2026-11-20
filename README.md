# PhishRadar — Autonomous Phishing URL & Malicious Domain Threat-Intel Workbench

A dark SOC-style workbench that takes a suspicious URL through a 5-node pipeline and returns a verdict (`SAFE` / `SUSPICIOUS` / `MALICIOUS PHISHING`), a 0–100 threat score, live RDAP and TLS telemetry, and a ready-to-send takedown brief. It opens straight into the workbench, with no landing page and no login.

## Run it (one command)

**Windows:** double-click `start.bat` (or run it in a terminal)
**Linux / macOS / VPS:** `bash start.sh`

The script creates `.venv`, installs the 5 dependencies, starts the server and opens <http://127.0.0.1:8003>.
Manual route: `pip install -r requirements.txt && python run.py`

Needs Python 3.10+. **No API key is required.** Without one, the deterministic engine still scores every URL, and a key adds AI reasoning.

## The 5-node pipeline (`app/pipeline.py`, pure Python)

| # | Node | What it does |
|---|------|--------------|
| 1 | URL Gatekeeper & Anatomy Parser | Rejects non-URLs; splits scheme / subdomains / registrable domain / TLD / path / query; checks IP-literal, `@`, punycode, brand look-alikes (homoglyph, typosquat, subdomain spoof); Shannon entropy |
| 2 | RDAP / WHOIS Telemetry | `rdap.org`, 4s timeout, run in parallel with Node 3 (or IP2WHOIS if a key is set, with silent RDAP fallback): registrar, creation date, age, newly-registered (<90d) and NXDOMAIN flags |
| 3 | Live TLS Inspector | Real handshake on :443 (3.5s timeout) with `ssl` + `socket`: issuer, validity, days left, SAN count, self-signed / expired / mismatch. Probes to private IPs are blocked. |
| 4 | AI Brand & Phishing Classifier | One structured JSON call (900 max tokens, 18s cap). Groq-only: `openai/gpt-oss-120b` with automatic fallback to `qwen/qwen3.8-27b`, then `llama-3.3-70b-versatile`. A failing provider is skipped for 120s (circuit breaker). The AI score can move at most ±30 from the deterministic evidence score. |
| 5 | SOC Brief & Persistence | DNS / proxy / email / firewall rules, abuse-report text, defanged IOCs; saved to SQLite |

Responses stream as NDJSON (`start` → `node` → `result`); a full scan takes roughly 5–12s.

## Features

- **Tabs:** Single URL Inspector · URL Diff & Compare (any two history scans) · IOC Threat Report (Copy Defanged IOCs, Download `.md`)
- **Live timer + Execution & Debug Logs:** a 0.1s-tick elapsed timer on the pipeline banner, plus a collapsible panel with per-node ms, RDAP/TLS probe latency, active AI provider (tagged `(fallback)` if Groq answered) and raw NDJSON events.
- **Demo rate limit:** a sliding window of 15 scans per hour (SQLite), returning HTTP 429 with the minutes and seconds left. Invalid input never uses a slot. Change the limit with `DEMO_SCAN_LIMIT`.
- **BYOK:** the *API Keys* modal saves keys to `phishradar.db`; `.env` also works (see `.env.example`). The dot is green when an AI key is available.

## Dependencies

`fastapi`, `uvicorn`, `httpx`, `python-dotenv`, `python-multipart`. There are no LangChain/LangGraph packages and no `uvicorn[standard]`, so uvloop, httptools and watchfiles are not pulled in. FastAPI itself depends on `pydantic-core`, which ships as a compiled extension. If Windows Smart App Control blocks it, see Troubleshooting.

## Troubleshooting

- **Smart App Control blocks a `.pyd` on startup:** `pydantic-core` is the one unavoidable compiled dependency of FastAPI. Run on Linux/WSL with `start.sh`, or turn off Smart App Control.
- **Every URL says "no AI key":** add a Groq key (`GROQ_API_KEY`). The model names are configurable in `.env` if your account exposes different ones.
- **RDAP shows "unavailable":** some registries rate-limit `rdap.org`. Retry later, or add an IP2WHOIS key.

## Safety notes

URLs are only parsed and probed with a TLS handshake. PhishRadar never fetches or renders page content. All IOCs are defanged (`hxxp[://]evil[.]com`). The sample "typosquat" and "spoof" URLs are expected to be unregistered.


Run this command

Windows (PowerShell):
python -m venv .venv; .\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8003

macOS / Linux (Terminal):
python3 -m venv .venv && ./.venv/bin/python -m pip install -r requirements.txt
./.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8003
