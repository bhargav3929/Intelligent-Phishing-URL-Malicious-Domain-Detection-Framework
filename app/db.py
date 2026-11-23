"""SQLite persistence: scan history, saved API keys, demo ticket run counts."""
import json
import os
import sqlite3
import time
from pathlib import Path

from . import config

DB_PATH = Path(__file__).resolve().parent.parent / "phishradar.db"
KEY_NAMES = ("GROQ_API_KEY", "IP2WHOIS_API_KEY")


def conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init() -> None:
    with conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL,
                url TEXT NOT NULL,
                brand TEXT,
                verdict TEXT,
                score INTEGER,
                result_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS ticket_runs(tid TEXT PRIMARY KEY, runs INTEGER NOT NULL DEFAULT 0, first_ts REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS daily_runs(day TEXT PRIMARY KEY, runs INTEGER NOT NULL DEFAULT 0);
            """
        )
        cols = [r["name"] for r in c.execute("PRAGMA table_info(scans)")]
        if "owner" not in cols:  # history is private per visitor (ticket id in demo mode)
            c.execute("ALTER TABLE scans ADD COLUMN owner TEXT NOT NULL DEFAULT 'local'")
    cleanup()


_last_cleanup = 0.0


def maybe_cleanup() -> None:
    """Run cleanup() at most every 10 minutes, so a long-running demo server keeps its 24-hour promise."""
    global _last_cleanup
    if config.demo_mode() and time.time() - _last_cleanup > 600:
        _last_cleanup = time.time()
        cleanup()


def cleanup() -> None:
    """Demo mode: delete ticket run counts and history older than 24 hours."""
    if not config.demo_mode():
        return
    cutoff = time.time() - 86400
    with conn() as c:
        old = [r["tid"] for r in c.execute("SELECT tid FROM ticket_runs WHERE first_ts < ?", (cutoff,))]
        for tid in old:
            c.execute("DELETE FROM scans WHERE owner=?", (tid,))
        c.execute("DELETE FROM ticket_runs WHERE first_ts < ?", (cutoff,))
        c.execute("DELETE FROM scans WHERE owner!='local' AND created_at < ?", (cutoff,))


# ---------- demo ticket run counting ----------
def _today() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def ticket_runs(tid: str) -> int:
    with conn() as c:
        row = c.execute("SELECT runs FROM ticket_runs WHERE tid=?", (tid,)).fetchone()
    return row["runs"] if row else 0


def daily_runs() -> int:
    with conn() as c:
        row = c.execute("SELECT runs FROM daily_runs WHERE day=?", (_today(),)).fetchone()
    return row["runs"] if row else 0


def record_demo_run(tid: str) -> None:
    with conn() as c:
        c.execute("INSERT INTO ticket_runs(tid,runs,first_ts) VALUES(?,1,?) ON CONFLICT(tid) DO UPDATE SET runs=runs+1", (tid, time.time()))
        c.execute("INSERT INTO daily_runs(day,runs) VALUES(?,1) ON CONFLICT(day) DO UPDATE SET runs=runs+1", (_today(),))


# ---------- keys ----------
def key_source(name: str) -> tuple[str, str]:
    """Return (value, source) with source in ui|env|none. Demo mode ignores saved keys."""
    if not config.demo_mode():
        with conn() as c:
            row = c.execute("SELECT value FROM settings WHERE key=?", (name,)).fetchone()
        if row and row["value"] and _ok(name, row["value"]):
            return row["value"], "ui"
    v = os.getenv(name, "").strip()
    return (v, "env") if _ok(name, v) else ("", "none")


def _ok(name: str, v: str) -> bool:
    v = v.strip()
    if name == "GROQ_API_KEY":
        return config.key_usable(v)
    return bool(v) and v not in config.PLACEHOLDERS and " " not in v


def get_key(name: str) -> str:
    return key_source(name)[0]


def set_key(name: str, value: str) -> None:
    if name not in KEY_NAMES:
        raise ValueError("unknown key")
    with conn() as c:
        if value:
            c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (name, value))
        else:
            c.execute("DELETE FROM settings WHERE key=?", (name,))


def all_keys() -> dict:
    return {n: get_key(n) for n in KEY_NAMES}


# ---------- scans ----------
def save_scan(result: dict, owner: str = "local") -> int:
    with conn() as c:
        cur = c.execute(
            "INSERT INTO scans(created_at,url,brand,verdict,score,result_json,owner) VALUES(?,?,?,?,?,?,?)",
            (result["created_at"], result["url"], result.get("brand_input") or "", result["verdict"], result["risk_score"], json.dumps(result), owner),
        )
        return cur.lastrowid


def update_scan(scan_id: int, result: dict) -> None:
    with conn() as c:
        c.execute("UPDATE scans SET result_json=? WHERE id=?", (json.dumps(result), scan_id))


def list_scans(owner: str = "local", limit: int = 100) -> list:
    with conn() as c:
        rows = c.execute("SELECT id,created_at,url,brand,verdict,score FROM scans WHERE owner=? ORDER BY id DESC LIMIT ?", (owner, limit)).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: int, owner: str = "local"):
    with conn() as c:
        row = c.execute("SELECT result_json FROM scans WHERE id=? AND owner=?", (scan_id, owner)).fetchone()
    if not row:
        return None
    data = json.loads(row["result_json"])
    data["id"] = scan_id
    return data


def delete_scan(scan_id: int, owner: str = "local") -> None:
    with conn() as c:
        c.execute("DELETE FROM scans WHERE id=? AND owner=?", (scan_id, owner))
