r"""Re-record samples/results/*.json from REAL live runs (needs a Groq key in .env or saved in the app).

Run from the project folder:   .venv\Scripts\python tools\record_samples.py     (Windows)
                               .venv/bin/python tools/record_samples.py           (macOS / Linux)
A result is saved only if the AI step really succeeded, so the saved files are never hand-made.
"""
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import db, pipeline  # noqa: E402  (loads .env via app.main below)
from app.main import SAMPLES_DIR  # noqa: E402,F401  (importing app.main runs load_dotenv)


async def record(sample: dict, keys: dict) -> dict | None:
    an = pipeline.gatekeeper(sample["url"])
    result = None
    async for ev in pipeline.run_pipeline(an, sample.get("brand", ""), keys, "recorder"):
        if ev["type"] == "result":
            result = ev["result"]
    return result


async def main() -> int:
    keys = db.all_keys()
    if not keys.get("GROQ_API_KEY"):
        print("No usable Groq key. Put GROQ_API_KEY=gsk_... in .env (or save it in the app's API Keys) and run again.")
        return 1
    failed = 0
    for f in sorted(SAMPLES_DIR.glob("*.json")):
        sample = json.loads(f.read_text(encoding="utf-8"))
        result = await record(sample, keys)
        if not result or not result["ai"].get("ok"):
            print(f"SKIPPED {sample['id']}: AI step did not succeed ({(result or {}).get('ai', {}).get('error', 'no result')})")
            failed += 1
            continue
        result.pop("id", None)
        out = SAMPLES_DIR / "results" / f"{sample['id']}.json"
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"saved {out.relative_to(ROOT)}  verdict={result['verdict']}  ai={result['ai']['provider']}")
    with db.conn() as c:  # keep the recorder's runs out of the user's history
        c.execute("DELETE FROM scans WHERE owner='recorder'")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
