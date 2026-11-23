# Viva notes: PhishRadar

**One line:** a 5-step pipeline that scores a suspicious URL using rules, live RDAP and TLS evidence, and a Groq language model, then writes a takedown brief.

## Key questions and answers

- **Why 5 steps?** Each step adds different evidence: URL structure, domain age, certificate, AI judgement, report. Steps 2 and 3 run at the same time to save seconds.
- **Why not trust the AI alone?** The rule engine gives a baseline score and hard floors/caps. The AI can move the score at most 30 points, so it cannot contradict strong evidence.
- **What if Groq is down or busy?** `app/ai.py` retries up to 3 times per model (1s, 2s, 4s + jitter, or Groq's "try again in Xs"), then uses `GROQ_FALLBACK_MODEL`. If both fail the user sees a plain message and the rule-based verdict is still shown.
- **What is a typosquat / subdomain spoof?** `paypa1.com` imitates `paypal.com`. `login.microsoftonline.com.evil.xyz` puts the real brand in the subdomain while the registrable domain is `evil.xyz`.
- **Is it safe to scan malware sites?** Yes. It never fetches page content. It only parses the URL, does an RDAP lookup and a TLS handshake. IOCs are defanged.
- **Where are keys stored?** In the local `phishradar.db` (git-ignored) or `.env`. Only the machine running the app can change them, and the full key is never sent back to the browser.
- **Limits?** None in the download version. The web demo limits live runs per ticket and per day (`DEMO_DAILY_CAP`).
- **Port?** 8003 (8000 + project number 3).
- **Why no Docker / heavy ML?** Students must start it with one command, so it uses only five small Python packages and SQLite.

## Files to know

`app/pipeline.py` (steps), `app/ai.py` (Groq calls), `app/main.py` (routes), `app/db.py` (storage), `app/config.py` (settings), `samples/` (inputs and saved results).
