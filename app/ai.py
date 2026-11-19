"""Node 4 LLM access: one structured JSON call, hedged provider race (Gemini first, Groq on error/slow), circuit breaker. Pure httpx."""
import asyncio
import json
import os
import re
import time

import httpx

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MAX_OUTPUT_TOKENS = 900
TOTAL_TIMEOUT = 18.0
HEDGE_AFTER = 5.0
BREAKER_SECONDS = 120.0

_breaker: dict = {}  # provider -> monotonic time until which it is skipped


class NoProvider(Exception):
    def __init__(self, msg, attempts=None):
        super().__init__(msg)
        self.attempts = attempts or []


def _models():
    return {
        "gemini": [os.getenv("GEMINI_MODEL", "gemini-3.8-flash")],
        "groq": [os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"), os.getenv("GROQ_FALLBACK_MODEL", "qwen/qwen3.8-27b")],
    }


def _tripped(provider: str) -> bool:
    return _breaker.get(provider, 0) > time.monotonic()


def _trip(provider: str) -> None:
    _breaker[provider] = time.monotonic() + BREAKER_SECONDS


async def _gemini(client, key, model, system, prompt):
    body = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": MAX_OUTPUT_TOKENS, "responseMimeType": "application/json"},
    }
    r = await client.post(GEMINI_URL.format(model=model), params={"key": key}, json=body)
    if r.status_code != 200:
        return r.status_code, None
    parts = r.json()["candidates"][0]["content"]["parts"]
    return 200, "".join(p.get("text", "") for p in parts)


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
    models = _models()
    attempts: list = []
    avail = []
    for provider, key_name, fn in (("gemini", "GEMINI_API_KEY", _gemini), ("groq", "GROQ_API_KEY", _groq)):
        if keys.get(key_name):
            avail.append((provider, fn, keys[key_name]))
    if not avail:
        raise NoProvider("No AI API key configured", attempts)
    live = [a for a in avail if not _tripped(a[0])] or avail  # if every provider is tripped, try anyway
    for a in avail:
        if a not in live:
            attempts.append({"provider": a[0], "ok": False, "ms": 0, "error": "circuit open (120s)"})

    deadline = time.monotonic() + TOTAL_TIMEOUT
    tasks: dict = {}

    def start(entry):
        provider, fn, key = entry
        t = asyncio.create_task(_run_provider(provider, fn, key, models[provider], system, prompt, attempts, TOTAL_TIMEOUT))
        tasks[t] = provider

    start(live[0])
    hedge = live[1] if len(live) > 1 else None
    hedge_at = time.monotonic() + HEDGE_AFTER
    errors = []
    try:
        while tasks:
            now = time.monotonic()
            if now >= deadline:
                break
            wait_for = deadline - now
            if hedge and hedge_at > now:
                wait_for = min(wait_for, hedge_at - now)
            done, _ = await asyncio.wait(set(tasks), timeout=wait_for, return_when=asyncio.FIRST_COMPLETED)
            for d in done:
                provider = tasks.pop(d)
                try:
                    text, label, model_fallback = d.result()
                except RuntimeError as e:
                    _trip(provider)
                    errors.append(str(e))
                    continue
                return text, label, {"fallback": provider == "groq" or model_fallback, "attempts": attempts}
            if hedge and (not tasks or time.monotonic() >= hedge_at):  # primary failed or exceeded 5s -> launch hedge
                start(hedge)
                hedge = None
    finally:
        timed_out = time.monotonic() >= deadline
        for t, provider in list(tasks.items()):
            if not t.done():
                t.cancel()
                if timed_out:
                    _trip(provider)
                    attempts.append({"provider": provider, "ok": False, "ms": int(TOTAL_TIMEOUT * 1000), "error": "timeout"})
    raise NoProvider("; ".join(errors) or "AI providers timed out", attempts)


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
