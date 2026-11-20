"""SQLite persistence: scan history, API keys, sliding-window rate limiter."""
import json
import os
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "phishradar.db"
WINDOW_SECONDS = 3600
KEY_NAMES = ("GROQ_API_KEY", "IP2WHOIS_API_KEY")


def _limit() -> int:
    try:
        return max(1, int(os.getenv("DEMO_SCAN_LIMIT", "15")))
    except ValueError:
        return 15


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
            CREATE TABLE IF NOT EXISTS rate_events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, client TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_rate ON rate_events(client, ts);
            """
        )


# ---------- keys ----------
def get_key(name: str) -> str:
    with conn() as c:
        row = c.execute("SELECT value FROM settings WHERE key=?", (name,)).fetchone()
    if row and row["value"]:
        return row["value"]
    return os.getenv(name, "").strip()


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


# ---------- rate limiter ----------
def rate_status(client: str) -> dict:
    now = time.time()
    limit = _limit()
    with conn() as c:
        c.execute("DELETE FROM rate_events WHERE ts < ?", (now - WINDOW_SECONDS,))
        rows = c.execute("SELECT ts FROM rate_events WHERE client=? ORDER BY ts ASC", (client,)).fetchall()
    used = len(rows)
    reset_in = int(rows[0]["ts"] + WINDOW_SECONDS - now) + 1 if rows else 0
    return {"limit": limit, "used": used, "remaining": max(0, limit - used), "reset_in_seconds": max(0, reset_in)}


def rate_consume(client: str) -> None:
    with conn() as c:
        c.execute("INSERT INTO rate_events(ts, client) VALUES(?,?)", (time.time(), client))


# ---------- scans ----------
def save_scan(result: dict) -> int:
    with conn() as c:
        cur = c.execute(
            "INSERT INTO scans(created_at,url,brand,verdict,score,result_json) VALUES(?,?,?,?,?,?)",
            (result["created_at"], result["url"], result.get("brand_input") or "", result["verdict"], result["risk_score"], json.dumps(result)),
        )
        return cur.lastrowid


def update_scan(scan_id: int, result: dict) -> None:
    with conn() as c:
        c.execute("UPDATE scans SET result_json=? WHERE id=?", (json.dumps(result), scan_id))


def list_scans(limit: int = 100) -> list:
    with conn() as c:
        rows = c.execute("SELECT id,created_at,url,brand,verdict,score FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: int):
    with conn() as c:
        row = c.execute("SELECT result_json FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return None
    data = json.loads(row["result_json"])
    data["id"] = scan_id
    return data


def delete_scan(scan_id: int) -> None:
    with conn() as c:
        c.execute("DELETE FROM scans WHERE id=?", (scan_id,))
