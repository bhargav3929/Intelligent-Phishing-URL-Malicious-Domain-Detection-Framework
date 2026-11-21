# PhishRadar: Phishing URL & Malicious Domain Threat-Intel Workbench

PhishRadar takes a suspicious web address and checks it in five steps. It then gives a verdict (`SAFE`, `SUSPICIOUS` or `MALICIOUS PHISHING`), a 0-100 threat score, live domain-age and certificate details, and a ready-to-send takedown report. It is made for students and security analysts who want to see how a phishing check works. It never opens or downloads the page itself.

## What you need

- **Python 3.10 or newer.** Download it from <https://www.python.org/downloads/>. On Windows, tick "Add python.exe to PATH".
- **A free Groq key** for the AI step: <https://console.groq.com/keys> (about 1 minute, no card). Without a key the app still scores every URL with its rule engine, and it tells you the AI step was skipped.
- An internet connection (for the domain and certificate checks).

## Run it (one command)

- **macOS / Linux:** `chmod +x start.sh && ./start.sh`
- **Windows:** double-click `start.bat`

The script sets up a private Python environment, installs the packages, starts the server and opens your browser at <http://127.0.0.1:8003>. Run it again any time. It is fast after the first run.

## Add your Groq key

Click **API Keys** in the app and paste your key (it starts with `gsk_`). Or open the `.env` file and set `GROQ_API_KEY=` to your key, then restart.

## How to use it

1. Click one of the three sample chips (a safe site, a typosquat and a subdomain spoof). The saved result opens at once.
2. Press **Inspect Target URL** to run that URL live through all five steps (about 5-12 seconds).
3. Now paste your own URL, optionally type the brand you think it imitates, and press **Inspect Target URL**.
4. Open **IOC Threat Report** to copy the defanged indicators or download the report. Open **URL Diff & Compare** to compare two past scans.

You get 15 full scans per hour. A wrong URL, or a scan where the AI step fails, does not use one up.

## How it works

URL → five steps → verdict → report.

| # | Step | What it does |
|---|------|--------------|
| 1 | URL gatekeeper | Splits the URL into parts and looks for look-alike brands, odd characters and lure words (`app/pipeline.py`) |
| 2 | RDAP / WHOIS | Looks up the registrar and how old the domain is (free `rdap.org`) |
| 3 | TLS check | Makes a real HTTPS handshake and reads the certificate |
| 4 | AI classifier | Sends the evidence to Groq (`app/ai.py`). It retries when Groq is busy and switches to a backup model. The AI can only move the score by 30 points from the rule-based score. |
| 5 | SOC brief | Writes firewall, DNS and email rules, an abuse report and defanged indicators, and saves the scan to a local SQLite file (`app/db.py`) |

Results stream to the page step by step, so you see each step finish.

## Project structure

```
03-phishradar-threat-intel/
├── start.sh / start.bat     one-command start
├── run.py                   optional: python run.py
├── requirements.txt         pinned packages
├── .env.example             settings (copied to .env on first run)
├── app/
│   ├── main.py              web server and routes
│   ├── config.py            settings read from .env
│   ├── ai.py                the only file that talks to Groq
│   ├── pipeline.py          the five steps
│   ├── db.py                SQLite: history, saved keys, scan limit
│   └── static/              index.html, app.js, style.css
└── samples/                 sample URLs; samples/results/ holds their saved results
```

## Troubleshooting

- **Port already in use:** another program is using port 8003. Close it, or change `PORT=` in `.env` and run the start script again.
- **"The AI service is busy right now":** Groq's free tier is overloaded. Wait a minute and press the button again. This does not use up a scan.
- **"Your Groq key was rejected":** open **API Keys** and paste a fresh key from <https://console.groq.com/keys>.
- **Python not found:** install Python 3.10+ from <https://www.python.org/downloads/> and, on Windows, tick "Add python.exe to PATH". Then run the start script again.
- **Install failed:** check your internet connection and run the start script again. It carries on where it stopped.
- **Windows blocks a `.pyd` file:** Smart App Control can block `pydantic-core`, which FastAPI needs. Turn off Smart App Control, or run the app with WSL.
- **RDAP shows "unavailable":** `rdap.org` is rate-limiting you. Try again later, or add an IP2WHOIS key in **API Keys**.

All indicators are defanged (`hxxp[://]evil[.]com`). The sample typosquat and spoof domains are expected to be unregistered.

Run the Commands:

Windows (PowerShell):
python -m venv .venv; .\.venv\Scripts\python.exe -m pip install -r requirements.txt; .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8003

macOS / Linux (Terminal):
python3 -m venv .venv && ./.venv/bin/python -m pip install -r requirements.txt && ./.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8003