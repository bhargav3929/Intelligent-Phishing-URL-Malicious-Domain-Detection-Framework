"""PhishRadar FastAPI app — serves the workbench UI at / and the JSON/NDJSON API."""
import json
import time
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE = Path(__file__).resolve().parent
load_dotenv(BASE.parent / ".env")

from . import db, pipeline  # noqa: E402  (after dotenv so env is loaded)

app = FastAPI(title="PhishRadar", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
db.init()


def client_id(request: Request) -> str:
    return request.client.host if request.client else "local"


class ScanReq(BaseModel):
    url: str = ""
    brand: str = ""


class KeysReq(BaseModel):
    groq: str | None = None
    ip2whois: str | None = None


@app.get("/")
def index():
    return FileResponse(BASE / "static" / "index.html", headers={"Cache-Control": "no-store"})


@app.get("/api/rate")
def rate(request: Request):
    return db.rate_status(client_id(request))


@app.post("/api/scan")
async def scan(req: ScanReq, request: Request):
    t = time.perf_counter()
    an = pipeline.gatekeeper(req.url)
    an["ms"] = int((time.perf_counter() - t) * 1000)
    if not an["ok"]:  # invalid input never consumes quota
        return JSONResponse({"detail": an["error"], "node": 1}, status_code=422)
    cid = client_id(request)
    st = db.rate_status(cid)
    if st["remaining"] <= 0:
        s = st["reset_in_seconds"]
        return JSONResponse(
            {"detail": f"Demo limit of {st['limit']} scans/hour reached. Next slot in {s // 60}m {s % 60:02d}s.", "retry_after_seconds": s, "rate": st},
            status_code=429, headers={"Retry-After": str(s)},
        )
    db.rate_consume(cid)
    keys = db.all_keys()
    brand = req.brand.strip()[:60]

    async def stream():
        try:
            async for ev in pipeline.run_pipeline(an, brand, keys):
                yield json.dumps(ev) + "\n"
        except Exception as e:  # surface unexpected failures to the UI instead of a dead stream
            yield json.dumps({"type": "error", "detail": f"{type(e).__name__}: {e}"}) + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson")


@app.get("/api/history")
def history():
    return db.list_scans()


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):
    s = db.get_scan(scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    return s


@app.delete("/api/scans/{scan_id}")
def del_scan(scan_id: int):
    db.delete_scan(scan_id)
    return {"ok": True}


@app.get("/api/scans/{scan_id}/report.md")
def report(scan_id: int):
    s = db.get_scan(scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    return PlainTextResponse(s["report_md"], headers={"Content-Disposition": f'attachment; filename="phishradar-report-{scan_id}.md"'})


def _mask(v: str) -> str:
    return "" if not v else (v[:4] + "…" + v[-4:] if len(v) > 10 else "••••")


@app.get("/api/keys")
def keys_status():
    k = db.all_keys()
    return {n: {"set": bool(k[e]), "masked": _mask(k[e])} for n, e in (("groq", "GROQ_API_KEY"), ("ip2whois", "IP2WHOIS_API_KEY"))}


@app.post("/api/keys")
def save_keys(req: KeysReq):
    # None = leave unchanged, "" = clear, otherwise save
    for field, name in (("groq", "GROQ_API_KEY"), ("ip2whois", "IP2WHOIS_API_KEY")):
        v = getattr(req, field)
        if v is not None:
            db.set_key(name, v.strip()[:200])
    return keys_status()
