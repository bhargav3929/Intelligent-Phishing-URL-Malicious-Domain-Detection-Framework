"""PhishRadar 5-node threat-intel pipeline — pure Python (urllib, ssl, socket, math, httpx)."""
import asyncio
import ipaddress
import json
import math
import re
import socket
import ssl
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlsplit

import httpx

from . import ai, db

# ---------------------------------------------------------------- constants
MULTI_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "net.in", "org.in",
    "co.jp", "com.br", "com.cn", "co.nz", "co.za", "com.mx", "com.sg", "com.tr", "com.ar", "co.kr",
}
RISKY_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "zip", "mov", "work", "country", "support",
    "icu", "buzz", "rest", "cyou", "monster", "shop", "live", "cam", "loan", "men", "link",
}
KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure", "security", "account", "update",
    "billing", "password", "passwd", "wallet", "confirm", "suspend", "unlock", "recover", "reset",
    "oauth", "authorize", "invoice", "payment", "banking", "support", "alert",
]
# brand -> legitimate registrable domains
BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "microsoft": ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com", "outlook.com", "azure.com"],
    "google": ["google.com", "gmail.com", "youtube.com", "googleapis.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com", "amazonaws.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "github": ["github.com", "githubusercontent.com", "github.io"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "hdfcbank": ["hdfcbank.com"],
    "icicibank": ["icicibank.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "whatsapp": ["whatsapp.com"],
}
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
LEET = str.maketrans({"1": "l", "0": "o", "3": "e", "5": "s", "4": "a", "7": "t", "$": "s"})


# ---------------------------------------------------------------- helpers
def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def defang(url: str) -> str:
    out = re.sub(r"^http", "hxxp", url, flags=re.I)
    out = out.replace("://", "[://]", 1)
    m = re.match(r"^(\S+?\[://\])([^/?#]*)(.*)$", out)
    if m:
        out = m.group(1) + m.group(2).replace(".", "[.]") + m.group(3)
    return out


def defang_host(host: str) -> str:
    return host.replace(".", "[.]")


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def now_ts() -> float:
    return time.time()


def _is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast or a.is_unspecified)


# ---------------------------------------------------------------- NODE 1
def gatekeeper(raw: str) -> dict:
    """Validate + decompose. Returns {'ok': bool, 'error': str, ...anatomy}."""
    raw = (raw or "").strip()
    if not raw:
        return {"ok": False, "error": "Empty input. Paste a full URL such as https://example.com/login."}
    if len(raw) > 2048 or re.search(r"\s", raw):
        return {"ok": False, "error": "Input is not a valid URL (whitespace or excessive length)."}
    note = ""
    if "://" not in raw:
        if re.match(r"^[\w.-]+\.[a-zA-Z]{2,}([/?#:].*)?$", raw):
            raw = "https://" + raw
            note = "No scheme supplied — assumed https://"
        else:
            return {"ok": False, "error": "Gatekeeper rejected input: not a URL. Expected format https://host.tld/path."}
    try:
        sp = urlsplit(raw)
        host = (sp.hostname or "").lower().rstrip(".")
        port = sp.port
    except ValueError:
        return {"ok": False, "error": "Gatekeeper rejected input: malformed URL structure."}
    if sp.scheme.lower() not in ("http", "https"):
        return {"ok": False, "error": f"Unsupported scheme '{sp.scheme}'. Only http/https URLs are analysed."}

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    if not is_ip and not HOST_RE.match(host):
        return {"ok": False, "error": f"Gatekeeper rejected input: '{host or raw}' is not a valid public hostname."}

    if is_ip:
        subs, reg, tld = [], host, ""
    else:
        labels = host.split(".")
        two = ".".join(labels[-2:])
        if two in MULTI_TLDS and len(labels) >= 3:
            tld, reg, subs = two, ".".join(labels[-3:]), labels[:-3]
        else:
            tld, reg, subs = labels[-1], ".".join(labels[-2:]), labels[:-2]

    query_pairs = parse_qsl(sp.query, keep_blank_values=True)
    qtext = "".join(f"{k}{v}" for k, v in query_pairs)
    root_label = reg.split(".")[0] if not is_ip else ""
    path = sp.path or "/"
    haystack = (path + "?" + sp.query + " " + host).lower()
    kws = sorted({k for k in KEYWORDS if k in haystack})

    flags = []  # {sev: 'high'|'med'|'low', part, text, pts}

    def flag(sev, part, text, pts):
        flags.append({"sev": sev, "part": part, "text": text, "pts": pts})

    # Rule: IP host / '@' trick / punycode -> +45 ONCE in total (further matches are listed but score 0)
    obf_pts = [45]

    def obf(text):
        p = obf_pts[0]
        obf_pts[0] = 0
        flag("high", "domain", text, p)

    puny = any(l.startswith("xn--") for l in host.split("."))
    if is_ip:
        obf("Raw IP-address host (no registrable domain) [+45 obfuscation rule]")
    if "@" in sp.netloc:
        obf("'@' credential-redirect trick — real host hidden behind decoy userinfo [+45 obfuscation rule]")
    if puny:
        obf("Punycode (xn--) label — possible IDN homograph attack [+45 obfuscation rule]")
    if tld in RISKY_TLDS:
        flag("med", "tld", f".{tld} is a high-abuse TLD [+20]", 20)
    if len(subs) >= 3:
        flag("med", "subdomain", f"{len(subs)} stacked subdomain levels", 8)
    if sum(host.count(ch) for ch in "-") >= 3:
        flag("low", "domain", "Excessive hyphens in hostname", 5)
    h_ent = shannon(root_label)
    q_ent = shannon(qtext)
    if len(root_label) >= 12 and h_ent >= 3.8:
        flag("med", "domain", f"High-entropy domain label ({h_ent:.2f} bits) — possible DGA", 12)
    if len(qtext) >= 12 and q_ent >= 3.5:
        flag("low", "path", f"High-entropy query string ({q_ent:.2f} bits) — tracking/session token", 8)
    if kws:
        in_host = any(k in host for k in kws)
        pts = min(20, 5 * len(kws)) if in_host else min(9, 3 * len(kws))
        flag("med" if in_host else "low", "path", "Credential-lure keywords: " + ", ".join(kws), pts)

    # brand logic
    brand_hits = []
    norm_host = host.translate(LEET)
    for brand, legit in BRANDS.items():
        if reg in legit or reg.endswith(tuple("." + d for d in legit)):
            continue  # genuinely that brand
        sub_part = ".".join(subs).lower()
        if brand in sub_part:
            brand_hits.append((brand, "subdomain"))
        elif brand in root_label:
            brand_hits.append((brand, "root"))
        elif brand in norm_host and brand not in host:
            brand_hits.append((brand, "homoglyph"))
        elif root_label.translate(LEET) and 3 <= len(brand) and levenshtein(root_label.translate(LEET), brand) <= 1 and root_label != brand:
            brand_hits.append((brand, "typosquat"))
    seen = set()
    bp = 55  # Rule: brand spoofing / typosquatting -> +55 ONCE in total
    for brand, how in brand_hits:
        if brand in seen:
            continue
        seen.add(brand)
        if how == "subdomain":
            flag("high", "subdomain", f"Brand '{brand}' used as subdomain of unrelated domain {reg} [+55 brand-spoof rule]", bp)
        elif how == "homoglyph":
            flag("high", "domain", f"Homoglyph/leet substitution mimicking '{brand}' [+55 brand-spoof rule]", bp)
        elif how == "typosquat":
            flag("high", "domain", f"Edit-distance-1 typosquat of '{brand}' [+55 brand-spoof rule]", bp)
        else:
            flag("high", "domain", f"Brand '{brand}' embedded in unrelated domain {reg} [+55 brand-spoof rule]", bp)
        bp = 0

    return {
        "ok": True,
        "normalized_url": raw,
        "note": note,
        "scheme": sp.scheme.lower(),
        "host": host,
        "port": port,
        "subdomains": subs,
        "registrable_domain": reg,
        "tld": tld,
        "root_label": root_label,
        "path": path,
        "query": sp.query,
        "query_params": [{"key": k, "value": v} for k, v in query_pairs],
        "is_ip": is_ip,
        "has_at_symbol": "@" in sp.netloc,
        "has_punycode": puny,
        "has_brand_spoof": bool(seen),
        "host_entropy": round(h_ent, 3),
        "query_entropy": round(q_ent, 3),
        "keywords": kws,
        "brand_candidates": sorted(seen),
        "flags": flags,
    }


# ---------------------------------------------------------------- NODE 2
def _vcard_fn(entity: dict) -> str:
    try:
        for item in entity["vcardArray"][1]:
            if item[0] == "fn":
                return item[3]
    except (KeyError, IndexError, TypeError):
        pass
    return ""


def _parse_dt(s: str):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None


async def rdap_lookup(domain: str, is_ip: bool, ip2whois_key: str = "") -> dict:
    out = {"source": "rdap.org", "status": "error", "registrar": "", "created": "", "expires": "", "age_days": None, "newly_registered": False, "detail": ""}
    if is_ip:
        out.update(status="skipped", detail="IP-literal host — no domain registration to query.")
        return out
    async with httpx.AsyncClient(timeout=httpx.Timeout(4.0), follow_redirects=True, headers={"Accept": "application/rdap+json"}) as c:
        if ip2whois_key:
            try:
                r = await c.get("https://api.ip2whois.com/v2", params={"key": ip2whois_key, "domain": domain})
                j = r.json()
                if r.status_code == 200 and j.get("create_date"):
                    created = _parse_dt(j["create_date"])
                    out.update(source="ip2whois", status="ok", registrar=(j.get("registrar") or {}).get("name", ""), created=j["create_date"], expires=j.get("expire_date", ""))
                    return _finish_age(out, created)
            except (httpx.HTTPError, ValueError):
                pass  # silently fall back to RDAP
        try:
            r = await c.get(f"https://rdap.org/domain/{domain}")
        except httpx.HTTPError as e:
            out["detail"] = f"RDAP unreachable ({type(e).__name__})"
            return out
        if r.status_code == 404:
            # rdap.org also answers 404 when a registry publishes no RDAP data (.me, shared hosts like github.io).
            # Only call the domain unregistered when it doesn't resolve in DNS either.
            if await _resolves(domain):
                out.update(status="no_record", detail="The registry publishes no public RDAP record for this domain, so its age is unknown.")
            else:
                out.update(status="unregistered", detail="Domain not found in RDAP and does not resolve in DNS — unregistered / NXDOMAIN target.")
            return out
        if r.status_code != 200:
            out["detail"] = f"RDAP returned HTTP {r.status_code}"
            return out
        try:
            j = r.json()
        except ValueError:
            out["detail"] = "RDAP returned non-JSON response"
            return out
    created = None
    for ev in j.get("events", []):
        a = ev.get("eventAction", "").lower()
        if a == "registration":
            out["created"] = ev.get("eventDate", "")
            created = _parse_dt(out["created"])
        elif a == "expiration":
            out["expires"] = ev.get("eventDate", "")
    for ent in j.get("entities", []):
        if "registrar" in ent.get("roles", []):
            out["registrar"] = _vcard_fn(ent)
            break
    out["status"] = "ok"
    out["domain_status"] = j.get("status", [])
    return _finish_age(out, created)


async def _resolves(domain: str) -> bool:
    try:
        await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, domain, None), timeout=3.0)
        return True
    except (OSError, asyncio.TimeoutError):
        return False


def _finish_age(out: dict, created):
    if created:
        out["age_days"] = max(0, (datetime.now(timezone.utc) - created).days)
        out["newly_registered"] = out["age_days"] < 90
    else:
        out["detail"] = out.get("detail") or "Creation date not published by registry."
    return out


# ---------------------------------------------------------------- NODE 3
def tls_probe(host: str, scheme: str, is_ip: bool) -> dict:
    out = {"status": "error", "https_enforced": scheme == "https", "issuer": "", "subject": "", "valid_from": "", "valid_to": "",
           "days_remaining": None, "san_count": 0, "tls_version": "", "self_signed": False, "expired": False,
           "hostname_mismatch": False, "detail": ""}
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        out.update(status="no_dns", detail="Host does not resolve (NXDOMAIN) — TLS probe skipped.")
        return out
    ips = sorted({i[4][0] for i in infos})
    out["resolved_ips"] = ips[:4]
    if not all(_is_public_ip(ip) for ip in ips):
        out.update(status="skipped", detail="Host resolves to a non-public address — probe blocked for safety.")
        return out
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=3.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                out["tls_version"] = ss.version() or ""
    except ssl.SSLCertVerificationError as e:
        msg = (e.verify_message or str(e)).lower()
        out["status"] = "invalid"
        out["detail"] = e.verify_message or "Certificate verification failed"
        out["expired"] = "expired" in msg
        out["self_signed"] = "self" in msg or "self-signed" in msg
        out["hostname_mismatch"] = "hostname" in msg or "doesn't match" in msg or "mismatch" in msg
        return out
    except (socket.timeout, TimeoutError):
        out.update(status="timeout", detail="TLS handshake timed out (3.5s) — host offline, filtered or defanged.")
        return out
    except ssl.SSLError as e:
        out.update(status="error", detail=f"TLS handshake failed: {e.reason or e}")
        return out
    except OSError as e:
        out.update(status="unreachable", detail=f"Port 443 unreachable ({e.__class__.__name__}) — no HTTPS listener.")
        return out

    def rdn(seq):
        d = {k: v for part in seq for k, v in part}
        return d.get("organizationName") or d.get("commonName") or ""

    out["issuer"] = rdn(cert.get("issuer", ())) + (f" ({dict(p[0] for p in cert.get('issuer', ())).get('commonName', '')})" if cert.get("issuer") else "")
    out["subject"] = dict(p[0] for p in cert.get("subject", ())).get("commonName", "")
    nb, na = cert.get("notBefore"), cert.get("notAfter")
    if nb and na:
        f, t = ssl.cert_time_to_seconds(nb), ssl.cert_time_to_seconds(na)
        out["valid_from"] = datetime.fromtimestamp(f, timezone.utc).strftime("%Y-%m-%d")
        out["valid_to"] = datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d")
        out["days_remaining"] = int((t - time.time()) // 86400)
        out["cert_lifetime_days"] = int((t - f) // 86400)
    out["san_count"] = len(cert.get("subjectAltName", ()))
    out["status"] = "valid"
    out["detail"] = "Certificate chain and hostname verified against the system trust store."
    return out


# ---------------------------------------------------------------- scoring
def baseline(an: dict, rd: dict, tl: dict) -> dict:
    """Deterministic rule engine. Returns score, flags, rules (human-readable log) plus
    floor/cap/safe_ok constraints that the AI refinement step may NOT override."""
    score = sum(f["pts"] for f in an["flags"])
    flags = [dict(f) for f in an["flags"]]
    rules = [f"{f['text']} (+{f['pts']})" for f in an["flags"] if f["pts"]]
    floor, cap = 0, None
    scheme = an["scheme"]
    spoof = bool(an.get("has_brand_spoof"))
    obf = an["is_ip"] or an["has_at_symbol"] or an["has_punycode"]
    kws = bool(an["keywords"])

    def add(sev, text, pts):
        nonlocal score
        score += pts
        flags.append({"sev": sev, "part": "infra", "text": text, "pts": pts})
        rules.append(f"{text} (+{pts})")

    # --- protocol & encryption rules
    if scheme == "http":
        if spoof or kws or an["is_ip"]:
            why = [n for n, c in (("brand spoofing/typosquatting", spoof), ("credential keywords", kws), ("IP host", an["is_ip"])) if c]
            add("high", "Unencrypted HTTP combined with " + ", ".join(why), 55)
            floor = max(floor, 65)
        else:
            add("med", "Unencrypted HTTP connection (Not Secure)", 30)
            floor = max(floor, 30)
            cap = 45  # dropped below if other evidence pushes the score past 45
    if spoof:
        floor = max(floor, 75)
    if obf:
        floor = max(floor, 45)

    # --- domain age rules
    age = rd.get("age_days")
    if rd["status"] == "unregistered":
        add("high", "Domain is unregistered / NXDOMAIN", 25)
    elif age is not None:
        if age < 30:
            add("high", f"Newly registered domain: {age} days old (<30d)", 30)
        elif age < 90:
            add("med", f"Recently registered domain: {age} days old (<90d)", 15)

    # --- TLS rules (https only)
    st = tl["status"]
    if scheme == "https" and st in ("invalid", "timeout", "unreachable", "error", "no_dns"):
        if tl["expired"]:
            reason = "TLS certificate expired"
        elif tl["self_signed"]:
            reason = "Self-signed TLS certificate"
        elif tl["hostname_mismatch"]:
            reason = "TLS certificate hostname mismatch"
        elif st == "invalid":
            reason = "TLS certificate failed verification"
        else:
            reason = "HTTPS requested but live TLS handshake failed"
        add("high", reason, 30)
        floor = max(floor, 30)
    elif st == "valid" and tl.get("cert_lifetime_days") and tl["cert_lifetime_days"] <= 100 and age is not None and age < 90:
        add("low", "Fresh short-lived certificate on a new domain", 5)

    # --- SAFE eligibility: https + live TLS ok + established domain + no spoofing/obfuscation/abuse-TLD flags
    established = (age is None and rd["status"] != "unregistered") or (age is not None and age >= 90)
    risky_lexical = spoof or obf or an["tld"] in RISKY_TLDS
    safe_ok = scheme == "https" and st == "valid" and established and not risky_lexical
    if safe_ok:
        rules.append("SAFE criteria met: https + live TLS valid + established domain (>=90d or RDAP unavailable) + no spoofing/lexical flags")
    else:
        miss = []
        if scheme != "https":
            miss.append("not https")
        if st != "valid":
            miss.append(f"TLS check '{st}'")
        if not established:
            miss.append("domain not established")
        if risky_lexical:
            miss.append("spoofing/obfuscation/high-abuse-TLD flag")
        rules.append("Not eligible for SAFE: " + ", ".join(miss))
        floor = max(floor, 25)

    score = max(0, min(100, score))
    if cap is not None and score > cap:
        cap = None
    return {"score": score, "flags": flags, "rules": rules, "floor": floor, "cap": cap, "safe_ok": safe_ok}


def verdict_for(score: int) -> str:
    return "SAFE" if score < 25 else "SUSPICIOUS" if score < 60 else "MALICIOUS"


def heuristic_vector(an: dict, score: int) -> str:
    if score < 25:
        return "Benign"
    kinds = [f["text"] for f in an["flags"]]
    if any("subdomain of unrelated" in t for t in kinds):
        return "Subdomain Takeover/Spoof"
    if any("Homoglyph" in t or "typosquat" in t or "Punycode" in t for t in kinds):
        return "Typosquatting"
    if an["keywords"]:
        return "Credential Harvesting"
    return "Credential Harvesting" if score >= 60 else "Typosquatting"


VECTORS = ["Credential Harvesting", "Typosquatting", "Subdomain Takeover/Spoof", "Malware Dropper", "Benign"]

AI_SYSTEM = (
    "You are PhishRadar, an adversarial phishing-URL analyst in a SOC. You receive deterministic telemetry about a URL. "
    "Judge ONLY from the telemetry. Legitimate, long-established domains with valid TLS must be rated Benign with a low score. "
    "Respond with a single JSON object and nothing else."
)


def ai_prompt(an, rd, tl, base, brand_input):
    tele = {
        "url": an["normalized_url"], "user_suspected_brand": brand_input or None,
        "anatomy": {k: an[k] for k in ("scheme", "host", "subdomains", "registrable_domain", "tld", "path", "query", "is_ip", "has_at_symbol", "has_punycode", "host_entropy", "query_entropy", "keywords", "brand_candidates")},
        "rdap": {k: rd.get(k) for k in ("status", "registrar", "created", "age_days", "newly_registered")},
        "tls": {k: tl.get(k) for k in ("status", "issuer", "valid_to", "days_remaining", "self_signed", "expired", "hostname_mismatch", "detail")},
        "deterministic_flags": [f["text"] for f in base["flags"]], "deterministic_score": base["score"],
    }
    return (
        "Telemetry:\n" + json.dumps(tele, indent=1) +
        "\n\nReturn JSON with keys: risk_score (integer 0-100), attack_vector (one of " + ", ".join(VECTORS) + "), "
        "impersonated_brand (string or null), confidence (0-1), reasoning (2-4 sentences), red_flags (array of short strings), "
        "recommended_actions (array of short strings)."
    )


# ---------------------------------------------------------------- NODE 5 helpers
def soc_rules(res: dict) -> dict:
    an, v = res["anatomy"], res["verdict"]
    host, reg = an["host"], an["registrable_domain"]
    rules = []
    if v == "SAFE":
        rules = ["No containment required — allow, retain in passive monitoring.", "Re-scan if the domain's DNS/TLS posture changes."]
    else:
        rules = [
            f"DNS: sinkhole/block {defang_host(reg)} and all subdomains (*.{defang_host(reg)}).",
            f"Proxy/Web gateway: block URL {res['defanged']}.",
            "Email gateway: quarantine messages containing the URL; purge delivered copies from mailboxes.",
            "Hunt: search proxy/DNS logs for the last 30 days for hosts that resolved the domain; reset credentials of any user who submitted a form.",
        ]
        if res["tls"].get("resolved_ips"):
            rules.append("Firewall: block egress to " + ", ".join(defang_host(i) for i in res["tls"]["resolved_ips"]) + " (verify no shared hosting first).")
        if v == "MALICIOUS":
            rules.append("Submit to Google Safe Browsing, Microsoft SmartScreen and PhishTank for takedown.")
    registrar = res["rdap"].get("registrar") or "the domain registrar"
    abuse = (
        f"Subject: Phishing / abuse report for {defang_host(reg)}\n\n"
        f"To the abuse team at {registrar},\n\n"
        f"The domain {defang_host(reg)} is hosting content assessed as {res['attack_vector']} "
        f"({res['verdict']}, risk {res['risk_score']}/100)"
        + (f", impersonating {res['impersonated_brand']}" if res.get("impersonated_brand") else "")
        + f". Reported URL: {res['defanged']}\n"
        f"Evidence: " + "; ".join(f["text"] for f in res["flags"][:5]) + ".\n\n"
        "Please suspend the domain and preserve logs. Report generated by PhishRadar."
    )
    iocs = [res["defanged"], defang_host(host)] + ([defang_host(reg)] if reg != host else [])
    iocs += [defang_host(i) for i in res["tls"].get("resolved_ips", [])]
    return {"rules": rules, "abuse_report": abuse if v != "SAFE" else "", "iocs": list(dict.fromkeys(iocs))}


def build_report(res: dict) -> str:
    rd, tl, an = res["rdap"], res["tls"], res["anatomy"]
    ts = datetime.fromtimestamp(res["created_at"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    L = [
        "# PhishRadar — SOC Threat Intelligence Brief", "",
        f"**Generated:** {ts}  ", f"**Verdict:** {res['verdict']} — risk score {res['risk_score']}/100  ",
        f"**Attack vector:** {res['attack_vector']}  ", f"**Impersonated brand:** {res.get('impersonated_brand') or 'None identified'}  ",
        f"**Analysis engine:** {res['ai']['provider']}", "",
        "## Target", f"- Defanged URL: `{res['defanged']}`", f"- Registrable domain: `{defang_host(an['registrable_domain'])}`",
        f"- Host: `{defang_host(an['host'])}`", "",
        "## Assessment", res["ai"].get("reasoning") or "Deterministic engine verdict (no AI provider available).", "",
        "## Red flags",
    ]
    L += [f"- [{f['sev'].upper()}] {f['text']}" for f in res["flags"]] or ["- None"]
    L += ["", "## Telemetry",
          f"- Domain age: {str(rd['age_days']) + ' days' if rd.get('age_days') is not None else rd['status']} | Registrar: {rd.get('registrar') or 'n/a'} | Created: {rd.get('created') or 'n/a'}",
          f"- TLS: {tl['status']} | Issuer: {tl.get('issuer') or 'n/a'} | Valid to: {tl.get('valid_to') or 'n/a'} | Days left: {tl.get('days_remaining')}",
          f"- Entropy — host label {an['host_entropy']} bits, query {an['query_entropy']} bits", "",
          "## Indicators of Compromise (defanged)"]
    L += [f"- `{i}`" for i in res["soc"]["iocs"]]
    L += ["", "## Mitigation steps"] + [f"{n}. {r}" for n, r in enumerate(res["soc"]["rules"], 1)]
    if res["soc"]["abuse_report"]:
        L += ["", "## Abuse-contact report", "```", res["soc"]["abuse_report"], "```"]
    return "\n".join(L) + "\n"




# ---------------------------------------------------------------- orchestrator
def _ms(t: float) -> int:
    return int((time.perf_counter() - t) * 1000)


async def _timed_rdap(an, key):
    t = time.perf_counter()
    try:
        out = await asyncio.wait_for(rdap_lookup(an["registrable_domain"], an["is_ip"], key), 4.5)
    except asyncio.TimeoutError:
        out = {"source": "rdap.org", "status": "error", "registrar": "", "created": "", "expires": "", "age_days": None,
               "newly_registered": False, "detail": "RDAP timed out (4.0s)"}
    out["probe_ms"] = _ms(t)
    return out


async def _timed_tls(an):
    t = time.perf_counter()
    try:
        out = await asyncio.wait_for(asyncio.to_thread(tls_probe, an["host"], an["scheme"], an["is_ip"]), 3.5)
    except asyncio.TimeoutError:
        out = {"status": "timeout", "https_enforced": an["scheme"] == "https", "issuer": "", "subject": "", "valid_from": "", "valid_to": "",
               "days_remaining": None, "san_count": 0, "tls_version": "", "self_signed": False, "expired": False,
               "hostname_mismatch": False, "detail": "TLS probe timed out (3.5s) — host offline, filtered or slow DNS."}
    out["probe_ms"] = _ms(t)
    return out


async def run_pipeline(an: dict, brand_input: str, keys: dict, owner: str = "local"):
    """Async generator yielding NDJSON events: start -> node* -> result."""
    t0 = time.perf_counter()
    node_ms = {1: int(an.get("ms", 0))}

    def el():
        return round(time.perf_counter() - t0, 2)

    yield {"type": "start", "url": an["normalized_url"], "t": 0.0}
    yield {"type": "node", "n": 1, "status": "done", "ms": node_ms[1], "t": el(),
           "summary": f"{an['registrable_domain']} · entropy {an['host_entropy']} · {len(an['flags'])} lexical flags"}

    # Nodes 2 + 3 run concurrently; events stream as each probe finishes
    yield {"type": "node", "n": 2, "status": "running", "t": el()}
    yield {"type": "node", "n": 3, "status": "running", "t": el()}
    tasks = {asyncio.create_task(_timed_rdap(an, keys.get("IP2WHOIS_API_KEY", ""))): 2, asyncio.create_task(_timed_tls(an)): 3}
    results, pending = {}, set(tasks)
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for d in done:
            n = tasks[d]
            r = d.result()
            results[n] = r
            node_ms[n] = r["probe_ms"]
            if n == 2:
                ok = r["status"] in ("ok", "unregistered", "no_record", "skipped")
                if r["status"] == "ok":
                    summ = f"{r['registrar'] or 'registrar n/a'} · {r['age_days']}d old" if r.get("age_days") is not None else "age unknown"
                else:
                    summ = r["detail"] or r["status"]
            else:
                ok = r["status"] == "valid"
                summ = f"{r['issuer']} · {r['days_remaining']}d left" if ok else r["detail"]
            yield {"type": "node", "n": n, "status": "done" if ok else "warn", "ms": r["probe_ms"], "t": el(), "summary": summ}
    rd, tl = results[2], results[3]

    # Node 4 — single structured AI call, hedged provider race
    yield {"type": "node", "n": 4, "status": "running", "t": el()}
    t4 = time.perf_counter()
    base = baseline(an, rd, tl)
    ai_out = {"provider": "heuristic-engine", "ok": False, "error": "", "code": "", "fallback": False, "attempts": []}
    final_score = base["score"]
    vector = heuristic_vector(an, base["score"])
    brand = (an["brand_candidates"][0].title() if an["brand_candidates"] else None)
    if brand_input and base["score"] >= 30:
        brand = brand or brand_input.strip()
    try:
        j, provider, meta = await ai.classify_json(AI_SYSTEM, ai_prompt(an, rd, tl, base, brand_input), keys.get("GROQ_API_KEY", ""))
        ai_score = int(max(0, min(100, float(j.get("risk_score", base["score"])))))
        final_score = max(base["score"] - 30, min(base["score"] + 30, ai_score))  # AI refines, can't wildly contradict hard evidence
        if j.get("attack_vector") in VECTORS:
            vector = j["attack_vector"]
        if j.get("impersonated_brand"):
            brand = str(j["impersonated_brand"])
        elif final_score < 30:
            brand = None
        ai_out = {"provider": provider, "ok": True, "ai_score": ai_score, "confidence": j.get("confidence"),
                  "reasoning": str(j.get("reasoning", ""))[:1200], "red_flags": [str(x) for x in j.get("red_flags", [])][:10],
                  "recommended_actions": [str(x) for x in j.get("recommended_actions", [])][:8], "error": "",
                  "fallback": meta["fallback"], "attempts": meta["attempts"]}
    except ai.AIError as e:
        ai_out["error"] = str(e)  # plain-English message, never the raw provider error
        ai_out["code"] = e.code
        ai_out["attempts"] = list(e.attempts)
    except (ValueError, KeyError, TypeError):
        ai_out["error"] = ai.MESSAGES["AI_FAILED"]
        ai_out["code"] = "AI_FAILED"
    # Hard rule constraints always win over the AI refinement
    final_score = max(final_score, base["floor"])
    if base["cap"] is not None:
        final_score = min(final_score, base["cap"])
    final_score = max(0, min(100, final_score))
    verdict = verdict_for(final_score)
    base["rules"].append(f"Final verdict: {'MALICIOUS PHISHING' if verdict == 'MALICIOUS' else verdict} (risk {final_score}/100, rule floor {base['floor']})")
    if verdict == "SAFE":
        vector = "Benign"
    elif vector == "Benign":
        vector = heuristic_vector(an, max(final_score, 60))
    node_ms[4] = _ms(t4)
    if ai_out["ok"]:
        s4 = f"{verdict} · {final_score}/100 · {ai_out['provider']}{' (fallback)' if ai_out['fallback'] else ''}"
    else:
        s4 = f"Heuristic verdict {verdict} · {final_score}/100 (no AI: {ai_out['error'][:60] or 'no key'})"
    yield {"type": "node", "n": 4, "status": "done" if ai_out["ok"] else "warn", "ms": node_ms[4], "t": el(), "summary": s4}

    # Node 5
    yield {"type": "node", "n": 5, "status": "running", "t": el()}
    t5 = time.perf_counter()
    res = {
        "created_at": now_ts(), "url": an["normalized_url"], "brand_input": (brand_input or "").strip(),
        "defanged": defang(an["normalized_url"]), "verdict": verdict, "risk_score": final_score,
        "attack_vector": vector, "impersonated_brand": brand, "anatomy": an, "rdap": rd, "tls": tl, "ai": ai_out,
        "baseline_score": base["score"], "flags": base["flags"], "rules_triggered": base["rules"], "duration_ms": 0,
    }
    res["soc"] = soc_rules(res)
    res["report_md"] = build_report(res)
    res["id"] = db.save_scan(res, owner)
    node_ms[5] = _ms(t5)
    res["duration_ms"] = _ms(t0) + node_ms[1]
    res["debug"] = {"node_ms": node_ms, "rdap_ms": rd["probe_ms"], "tls_ms": tl["probe_ms"],
                    "ai_attempts": ai_out["attempts"], "rules_triggered": base["rules"], "total_ms": res["duration_ms"]}
    db.update_scan(res["id"], res)
    yield {"type": "node", "n": 5, "status": "done", "ms": node_ms[5], "t": el(),
           "summary": f"{len(res['soc']['rules'])} SOC rules · saved as scan #{res['id']}"}
    yield {"type": "result", "result": res, "t": el()}
