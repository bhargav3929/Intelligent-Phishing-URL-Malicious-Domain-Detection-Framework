"""Settings read from environment variables (.env for local runs). Every setting has a default."""
import base64
import hashlib
import hmac
import json
import os
import time

PLACEHOLDERS = {"your_groq_key_here", "your_ip2whois_key_here"}


def _bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None or not v.strip():
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "").strip() or default)
    except ValueError:
        return default


def project_name() -> str: return os.getenv("PROJECT_NAME", "PhishRadar")
def project_slug() -> str: return os.getenv("PROJECT_SLUG", "phishradar")
def project_number() -> int: return _int("PROJECT_NUMBER", 3)
def demo_mode() -> bool: return _bool("DEMO_MODE", False)
def trust_proxy() -> bool: return _bool("TRUST_PROXY", False)
def daily_cap() -> int: return _int("DEMO_DAILY_CAP", 200)
def max_upload_mb() -> int: return _int("DEMO_MAX_UPLOAD_MB", 3) if demo_mode() else _int("MAX_UPLOAD_MB", 8)
def ticket_secret() -> str: return os.getenv("DEMO_TICKET_SECRET", "").strip()
def groq_model() -> str: return os.getenv("GROQ_MODEL", "openai/gpt-oss-120b").strip()
def groq_fallback_model() -> str: return os.getenv("GROQ_FALLBACK_MODEL", "llama-3.3-70b-versatile").strip()


def key_usable(v: str | None) -> bool:
    """A key is usable only if non-empty, not a placeholder, no spaces, and starts with gsk_ (Groq)."""
    v = (v or "").strip()
    return bool(v) and v not in PLACEHOLDERS and " " not in v and v.startswith("gsk_")


# ---------------------------------------------------------------- demo ticket
def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_ticket(ticket: str | None, secret: str, slug: str):
    """Return (payload, None) if valid, else (None, error_code)."""
    if not ticket:
        return None, "TICKET_REQUIRED"
    if not secret:
        return None, "TICKET_INVALID"
    try:
        body, sig = ticket.split(".")
        payload = json.loads(_b64d(body))
        expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
        if payload.get("v") != 1 or not hmac.compare_digest(expected, _b64d(sig)):
            return None, "TICKET_INVALID"
    except Exception:
        return None, "TICKET_INVALID"
    if payload.get("slug") not in (slug, "*"):
        return None, "TICKET_INVALID"
    if int(payload.get("exp", 0)) < time.time():
        return None, "TICKET_EXPIRED"
    return payload, None


ERRORS = {
    "TICKET_REQUIRED": (401, "Sign in on lastsem.com to try your own input."),
    "TICKET_INVALID": (401, "This demo ticket isn't valid. Go back to lastsem.com and start again."),
    "TICKET_EXPIRED": (401, "This demo ticket has expired. Go back to lastsem.com and start again."),
    "TICKET_USED_UP": (429, "You've used all the live runs on this ticket. Samples still work."),
    "DAILY_CAP_REACHED": (429, "The demo has reached its daily limit. Try again tomorrow, or use the samples."),
}
