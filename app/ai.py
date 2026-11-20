"""Node 4 LLM access: one structured JSON call to Groq with automatic model fallback and a circuit breaker. Pure httpx."""
import asyncio
import json
import os
import re
import time

import httpx

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MAX_OUTPUT_TOKENS = 900
TOTAL_TIMEOUT = 18.0
BREAKER_SECONDS = 120.0

_breaker: dict = {}  # provider -> monotonic time until which it is skipped


class NoProvider(Exception):
    def __init__(self, msg, attempts=None):
        super().__init__(msg)
        self.attempts = attempts or []


def _models():
    return [
        os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
        os.getenv("GROQ_FALLBACK_MODEL", "qwen/qwen3.8-27b"),
        os.getenv("GROQ_FALLBACK_MODEL_2", "llama-3.3-70b-versatile"),
    ]


def _tripped(provider: str) -> bool:
    return _breaker.get(provider, 0) > time.monotonic()


def _trip(provider: str) -> None:
    _breaker[provider] = time.monotonic() + BREAKER_SECONDS


async def _groq(client, key, model, system, prompt):
    body = {
        "model": model, "temperature": 0.2, "max_tokens": MAX_OUTPUT_TOKENS,
        "response_format": {"type": "json_object"},
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
    }
    headers = {"Authorization": f"Bearer {key}"}
    r = await client.post(GROQ_URL, json=body, headers=headers)
    if r.status_code == 400:  # model may not support json mode
        body.pop("response_format")
        r = await client.post(GROQ_URL, json=body, headers=headers)
    if r.status_code != 200:
        return r.status_code, None
    return 200, r.json()["choices"][0]["message"]["content"]


async def _run_provider(provider, fn, key, models, system, prompt, attempts, timeout):
    """Try each model of one provider in order. Returns (text, 'provider/model', used_fallback_model) or raises RuntimeError."""
    async with httpx.AsyncClient(timeout=timeout) as client:
        for idx, model in enumerate(models):
            t = time.perf_counter()
            label = f"{provider}/{model}"
            try:
                status, text = await fn(client, key, model, system, prompt)
            except (httpx.HTTPError, KeyError, IndexError, ValueError) as e:
                attempts.append({"provider": label, "ok": False, "ms": int((time.perf_counter() - t) * 1000), "error": type(e).__name__})
                continue
            ms = int((time.perf_counter() - t) * 1000)
            if status == 200 and text:
                attempts.append({"provider": label, "ok": True, "ms": ms})
                return text, label, idx > 0
            attempts.append({"provider": label, "ok": False, "ms": ms, "error": f"HTTP {status}"})
            if status in (401, 403):
                break
    raise RuntimeError(f"{provider} failed")


async def classify(system: str, prompt: str, keys: dict):
    """Returns (text, provider_label, meta). meta = {fallback: bool, attempts: [...]}. Raises NoProvider."""
    key = keys.get("GROQ_API_KEY")
    attempts: list = []
    if not key:
        raise NoProvider("No Groq API key configured", attempts)
    if _tripped("groq"):
        attempts.append({"provider": "groq", "ok": False, "ms": 0, "error": "circuit open (120s)"})
        raise NoProvider("Groq circuit open", attempts)
    try:
        text, label, model_fallback = await asyncio.wait_for(
            _run_provider("groq", _groq, key, _models(), system, prompt, attempts, TOTAL_TIMEOUT), TOTAL_TIMEOUT)
    except asyncio.TimeoutError:
        _trip("groq")
        attempts.append({"provider": "groq", "ok": False, "ms": int(TOTAL_TIMEOUT * 1000), "error": "timeout"})
        raise NoProvider("Groq timed out", attempts)
    except RuntimeError as e:
        _trip("groq")
        raise NoProvider(str(e), attempts)
    return text, label, {"fallback": model_fallback, "attempts": attempts}


def parse_json(text: str) -> dict:
    text = text.strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    try:
        return json.loads(text)
    except ValueError:
        m = re.search(r"\{.*\}", text, re.S)
        if m:
            return json.loads(m.group(0))
        raise
