"""PhishRadar FastAPI app — serves the workbench UI at / and the JSON/NDJSON API."""
import json
import time
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent
SAMPLES_DIR = ROOT / "samples"
VERSION = "1.0.0"
load_dotenv(ROOT / ".env")

from . import config, db, pipeline  # noqa: E402  (after dotenv so env is loaded)

app = FastAPI(title="PhishRadar", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
db.init()
if config.demo_mode() and not config.ticket_secret():
    print("[PhishRadar] WARNING: DEMO_MODE=true but DEMO_TICKET_SECRET is empty - every ticket will be rejected.")


class ApiError(Exception):
    def __init__(self, code: str, message: str, status: int, **extra):
        self.code, self.message, self.status, self.extra = code, message, status, extra


def err_body(code: str, message: str, **extra) -> dict:
    return {"error": message, "code": code, **extra}


@app.exception_handler(ApiError)
async def _api_error(_: Request, e: ApiError):
    headers = {"Retry-After": str(e.extra["retry_after_seconds"])} if "retry_after_seconds" in e.extra else None
    return JSONResponse(err_body(e.code, e.message, **e.extra), status_code=e.status, headers=headers)


@app.exception_handler(StarletteHTTPException)
async def _http_error(_: Request, e: StarletteHTTPException):
    code = "NOT_FOUND" if e.status_code == 404 else "BAD_INPUT"
    return JSONResponse(err_body(code, "Not found." if code == "NOT_FOUND" else str(e.detail)), status_code=e.status_code)


@app.exception_handler(RequestValidationError)
async def _validation_error(_: Request, e: RequestValidationError):
    return JSONResponse(err_body("BAD_INPUT", "That request wasn't valid. Check the URL and try again."), status_code=400)


# ---------------------------------------------------------------- request helpers
def peer_ip(request: Request) -> str:
    if config.trust_proxy():
        xff = request.headers.get("x-forwarded-for", "")
        if xff.strip():
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "local"


def check_ticket(request: Request):
    """Demo mode: verify the ticket (no run is recorded here). Returns the payload, or raises ApiError."""
    payload, code = config.verify_ticket(request.headers.get("x-lastsem-ticket"), config.ticket_secret(), config.project_slug())
    if code:
        raise ApiError(code, config.ERRORS[code][1], config.ERRORS[code][0])
    if db.ticket_runs(payload["tid"]) >= int(payload.get("runs", 0)):
        raise ApiError("TICKET_USED_UP", config.ERRORS["TICKET_USED_UP"][1], 429)
    if db.daily_runs() >= config.daily_cap():
        raise ApiError("DAILY_CAP_REACHED", config.ERRORS["DAILY_CAP_REACHED"][1], 429)
    return payload


def owner_of(request: Request) -> str:
    """Whose history / quota this is: the ticket id in demo mode, the client address otherwise."""
    if config.demo_mode():
        payload, code = config.verify_ticket(request.headers.get("x-lastsem-ticket"), config.ticket_secret(), config.project_slug())
        return payload["tid"] if not code else "none"
    return "local" if peer_ip(request) in ("127.0.0.1", "::1", "local") else peer_ip(request)


class ScanReq(BaseModel):
    url: str = ""
    brand: str = ""


class KeysReq(BaseModel):
    groq_api_key: str | None = None
    ip2whois_api_key: str | None = None


@app.get("/")
def index():
    return FileResponse(BASE / "static" / "index.html", headers={"Cache-Control": "no-store"})


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/info")
def info(request: Request):
    demo = None
    if config.demo_mode():
        payload, code = config.verify_ticket(request.headers.get("x-lastsem-ticket"), config.ticket_secret(), config.project_slug())
        left = max(0, int(payload.get("runs", 0)) - db.ticket_runs(payload["tid"])) if payload else 0
        demo = {"ticket_valid": payload is not None, "runs_left": left, "daily_cap_reached": db.daily_runs() >= config.daily_cap()}
    return {
        "name": config.project_name(), "slug": config.project_slug(), "number": config.project_number(), "version": VERSION,
        "mode": "demo" if config.demo_mode() else "local",
        "ai": {"provider": "groq", "ready": bool(db.get_key("GROQ_API_KEY")), "model": config.groq_model()},
        "limits": {"max_upload_mb": config.max_upload_mb()},
        "demo": demo,
    }


# ---------------------------------------------------------------- samples
def _load_sample(sid: str):
    f = SAMPLES_DIR / f"{sid}.json"
    if not sid.replace("-", "").replace("_", "").isalnum() or not f.is_file():
        return None
    return json.loads(f.read_text(encoding="utf-8"))


def _saved_result(sid: str):
    f = SAMPLES_DIR / "results" / f"{sid}.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.is_file() else None


@app.get("/api/samples")
def samples():
    out = []
    for f in sorted(SAMPLES_DIR.glob("*.json")):
        s = json.loads(f.read_text(encoding="utf-8"))
        out.append({"id": s["id"], "title": s["title"], "input_text": s["url"], "brand": s.get("brand", ""),
                    "color": s.get("color", "#06B6D4"), "has_saved_result": (SAMPLES_DIR / "results" / f"{s['id']}.json").is_file()})
    return {"samples": out}


@app.get("/api/samples/{sample_id}")
def sample(sample_id: str):
    s = _load_sample(sample_id)
    if not s:
        raise ApiError("NOT_FOUND", "That sample doesn't exist.", 404)
    return {"id": s["id"], "title": s["title"], "input_text": s["url"], "brand": s.get("brand", ""), "result": _saved_result(sample_id)}


# ---------------------------------------------------------------- scan
@app.get("/api/rate")
def rate(request: Request):
    return db.rate_status(owner_of(request))


@app.post("/api/scan")
async def scan(req: ScanReq, request: Request):
    t = time.perf_counter()
    an = pipeline.gatekeeper(req.url)
    an["ms"] = int((time.perf_counter() - t) * 1000)
    if not an["ok"]:  # invalid input never consumes quota
        raise ApiError("BAD_INPUT", an["error"], 400, node=1)
    if config.demo_mode():
        check_ticket(request)
    owner = owner_of(request)
    st = db.rate_status(owner)
    if st["remaining"] <= 0:
        s = st["reset_in_seconds"]
        raise ApiError("RATE_LIMITED", f"Demo limit of {st['limit']} scans/hour reached. Next slot in {s // 60}m {s % 60:02d}s.", 429,
                       retry_after_seconds=s, rate=st)
    keys = db.all_keys()
    brand = req.brand.strip()[:60]

    async def stream():
        try:
            async for ev in pipeline.run_pipeline(an, brand, keys, owner):
                if ev["type"] == "result":
                    ai = ev["result"]["ai"]
                    # A failed AI run is never charged. Without any key there's no AI run to charge either.
                    if ai["ok"] or (ai.get("code") == "AI_NOT_CONFIGURED" and not config.demo_mode()):
                        db.rate_consume(owner)
                        if config.demo_mode():
                            db.record_demo_run(owner)
                yield json.dumps(ev) + "\n"
        except Exception as e:  # surface unexpected failures to the UI instead of a dead stream
            print(f"[PhishRadar] scan failed: {type(e).__name__}: {e}")
            yield json.dumps({"type": "error", **err_body("AI_FAILED", "The scan failed unexpectedly. Please try again.")}) + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson")


@app.get("/api/history")
def history(request: Request):
    return db.list_scans(owner_of(request))


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, request: Request):
    s = db.get_scan(scan_id, owner_of(request))
    if not s:
        raise ApiError("NOT_FOUND", "Scan not found.", 404)
    return s


@app.delete("/api/scans/{scan_id}")
def del_scan(scan_id: int, request: Request):
    db.delete_scan(scan_id, owner_of(request))
    return {"ok": True}


@app.get("/api/scans/{scan_id}/report.md")
def report(scan_id: int, request: Request):
    s = db.get_scan(scan_id, owner_of(request))
    if not s:
        raise ApiError("NOT_FOUND", "Scan not found.", 404)
    return PlainTextResponse(s["report_md"], headers={"Content-Disposition": f'attachment; filename="phishradar-report-{scan_id}.md"'})


# ---------------------------------------------------------------- keys (download version only)
KEY_ENV = {"groq": "GROQ_API_KEY", "ip2whois": "IP2WHOIS_API_KEY"}


def _mask(v: str) -> str:
    return "" if not v else (v[:4] + "…" + v[-4:] if len(v) > 10 else "••••")


def _keys_guard(request: Request, change: bool) -> None:
    if config.demo_mode():
        raise ApiError("NOT_FOUND", "Not found.", 404)
    if change:
        local = request.client is not None and request.client.host in ("127.0.0.1", "::1", "localhost")
        if not local or request.headers.get("x-forwarded-for") or request.headers.get("forwarded"):
            raise ApiError("KEYS_LOCAL_ONLY", "Keys can only be changed from the computer running PhishRadar.", 403)


def _keys_status() -> dict:
    out = {}
    for n, env in KEY_ENV.items():
        v, src = db.key_source(env)
        out[n] = {"configured": bool(v), "source": src, "masked": _mask(v)}
    return out


@app.get("/api/keys")
def keys_get(request: Request):
    _keys_guard(request, False)
    return _keys_status()


@app.post("/api/keys")
def keys_save(req: KeysReq, request: Request):
    _keys_guard(request, True)
    saved = []
    for field, name in (("groq_api_key", "groq"), ("ip2whois_api_key", "ip2whois")):
        v = (getattr(req, field) or "").strip()
        if not v:
            continue
        if len(v) > 200 or " " in v or (name == "groq" and not v.startswith("gsk_")):
            raise ApiError("BAD_INPUT", "That doesn't look like a valid key. Groq keys start with gsk_ and have no spaces.", 400)
        db.set_key(KEY_ENV[name], v)
        saved.append(name)
    return {"saved": saved}


@app.delete("/api/keys/{name}")
def keys_delete(name: str, request: Request):
    _keys_guard(request, True)
    if name not in KEY_ENV:
        raise ApiError("NOT_FOUND", "Unknown key.", 404)
    db.set_key(KEY_ENV[name], "")
    return {"removed": name}
