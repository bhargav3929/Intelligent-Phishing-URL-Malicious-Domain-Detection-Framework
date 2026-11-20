"""Node 4 LLM access: the only module that talks to Groq. Timeout, retries with backoff, model fallback, plain-English errors. Pure httpx."""
import asyncio
import json
import random
import re
import time

import httpx

from . import config

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MAX_OUTPUT_TOKENS = 900
REQUEST_TIMEOUT = 30.0
ATTEMPTS_PER_MODEL = 3
RETRY_STATUS = {429, 500, 502, 503, 504}

MESSAGES = {
    "AI_NOT_CONFIGURED": "No Groq key is set. Open API Keys and paste a free key from console.groq.com/keys.",
    "AI_KEY_INVALID": "Your Groq key was rejected. Open API Keys and paste a fresh key from console.groq.com/keys.",
    "AI_BUSY": "The AI service is busy right now. Wait a minute and try again.",
    "AI_FAILED": "The AI couldn't process this input.",
}


class AIError(Exception):
    """Carries a contract error code, a plain message for the user, and the attempt log."""
    def __init__(self, code, attempts=None):
        super().__init__(MESSAGES[code])
        self.code = code
        self.attempts = attempts or []


def _redact(text: str) -> str:
    return re.sub(r"gsk_[A-Za-z0-9_\-]+", "gsk_…", text or "")


def _models():
    primary, fallback = config.groq_model(), config.groq_fallback_model()
    return [primary] if not fallback or fallback == primary else [primary, fallback]


def _retry_wait(r: httpx.Response, attempt: int) -> float:
    """Exponential backoff (1s, 2s, 4s) plus jitter; honour Groq's 'try again in Xs' when X <= 20."""
    wait = 2 ** attempt + random.uniform(0, 0.5)
    if r is not None and r.status_code == 429:
        m = re.search(r"try again in ([\d.]+)\s*(ms|s)", r.text or "")
        if m:
            x = float(m.group(1)) / (1000 if m.group(2) == "ms" else 1)
            if x <= 20:
                wait = x + 0.2
    return wait


async def _call(client, key, model, system, prompt, attempts):
    """One model, up to 3 attempts. Returns text, or raises AIError (key invalid / bad input) or RuntimeError (busy)."""
    body = {
        "model": model, "temperature": 0.2, "max_tokens": MAX_OUTPUT_TOKENS,
        "response_format": {"type": "json_object"},
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
    }
    headers = {"Authorization": f"Bearer {key}"}
    for attempt in range(ATTEMPTS_PER_MODEL):
        t = time.perf_counter()
        r = None
        try:
            r = await client.post(GROQ_URL, json=body, headers=headers)
            if r.status_code == 400 and "response_format" in body:  # model may not support json mode
                body.pop("response_format")
                r = await client.post(GROQ_URL, json=body, headers=headers)
            err = f"HTTP {r.status_code}"
            if r.status_code == 200:
                text = r.json()["choices"][0]["message"]["content"]
                if text:
                    attempts.append({"provider": f"groq/{model}", "ok": True, "ms": int((time.perf_counter() - t) * 1000)})
                    return text
                err = "empty answer"
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as e:
            err = type(e).__name__
        attempts.append({"provider": f"groq/{model}", "ok": False, "ms": int((time.perf_counter() - t) * 1000), "error": err})
        if r is not None and r.status_code in (401, 403):
            raise AIError("AI_KEY_INVALID", attempts)
        if r is not None and r.status_code in (400, 413, 404):
            raise RuntimeError("rejected")  # not retryable; try the fallback model
        if attempt < ATTEMPTS_PER_MODEL - 1:
            await asyncio.sleep(_retry_wait(r, attempt))
    raise RuntimeError("busy")


async def classify(system: str, prompt: str, key: str):
    """Returns (text, 'groq/<model>', {fallback, attempts}). Raises AIError."""
    attempts: list = []
    if not config.key_usable(key):
        raise AIError("AI_NOT_CONFIGURED", attempts)
    busy = False
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        for idx, model in enumerate(_models()):
            try:
                text = await _call(client, key, model, system, prompt, attempts)
                return text, f"groq/{model}", {"fallback": idx > 0, "attempts": attempts}
            except AIError:
                raise
            except RuntimeError as e:
                busy = busy or str(e) == "busy"
    raise AIError("AI_BUSY" if busy else "AI_FAILED", attempts)


def parse_json(text: str) -> dict:
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S).strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    try:
        data = json.loads(text)
    except ValueError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            raise
        data = json.loads(m.group(0))
    if not isinstance(data, dict):
        raise ValueError("not an object")
    return data


async def classify_json(system: str, prompt: str, key: str):
    """classify() + parse; retries once when the answer isn't valid JSON. Returns (dict, label, meta)."""
    text, label, meta = await classify(system, prompt, key)
    try:
        return parse_json(text), label, meta
    except ValueError:
        text, label, meta2 = await classify(system, prompt, key)
        meta["attempts"] += meta2["attempts"]
        meta["fallback"] = meta["fallback"] or meta2["fallback"]
        try:
            return parse_json(text), label, meta
        except ValueError:
            raise AIError("AI_FAILED", meta["attempts"])
