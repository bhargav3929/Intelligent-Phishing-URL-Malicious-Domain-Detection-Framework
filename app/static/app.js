"use strict";
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const NODES = ["URL Gatekeeper & Anatomy Parser", "RDAP / WHOIS Domain Telemetry", "Live TLS/SSL Certificate Inspector", "AI Adversarial Brand & Phishing Classifier", "SOC Threat Brief & Persistence"];
const SAMPLES = [
  { label: "Verified Safe: github.com", url: "https://github.com/login", brand: "GitHub", c: "#10B981" },
  { label: "Typosquat Trap: paypa1-secure-verify.com", url: "http://paypa1-secure-verify.com/auth/update-billing?session=98a7f6d5", brand: "PayPal", c: "#EF4444" },
  { label: "Subdomain Spoof: login.microsoftonline.com.account-reset.xyz", url: "https://login.microsoftonline.com.account-reset.xyz/oauth2/authorize", brand: "Microsoft", c: "#F59E0B" },
];
const state = { scan: null, rate: null, rateAt: 0, busy: false, raw: [], timer: null };

/* ---------- helpers ---------- */
const fmtTime = s => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
const api = async (path, opts) => { const r = await fetch(path, opts); return r; };
const verdictLabel = v => v === "MALICIOUS" ? "MALICIOUS PHISHING" : v;
const col = v => v === "SAFE" ? "#10B981" : v === "SUSPICIOUS" ? "#F59E0B" : "#EF4444";
function toast(msg, kind = "") { $("#errBox").innerHTML = msg ? `<div class="err ${kind}">${esc(msg)}</div>` : ""; }
function openEl(id) { $("#" + id).classList.add("open"); $("#scrim").classList.add("on"); }
function closeAll() { document.querySelectorAll(".drawer.open,.modal.open").forEach(e => e.classList.remove("open")); $("#scrim").classList.remove("on"); }
document.addEventListener("click", e => { const c = e.target.closest("[data-close]"); if (c) closeAll(); });
$("#scrim").onclick = closeAll;
document.addEventListener("keydown", e => { if (e.key === "Escape") closeAll(); });

/* ---------- tabs ---------- */
$("#tabs").onclick = e => {
  const b = e.target.closest("button"); if (!b) return;
  document.querySelectorAll("#tabs button").forEach(x => x.classList.toggle("active", x === b));
  document.querySelectorAll(".view").forEach(v => v.classList.toggle("active", v.id === "view-" + b.dataset.tab));
  if (b.dataset.tab === "compare") renderCompare();
};

/* ---------- samples ---------- */
$("#samples").innerHTML = SAMPLES.map((s, i) => `<button class="chip" data-i="${i}"><i style="background:${s.c}"></i>${esc(s.label)}</button>`).join("");
$("#samples").onclick = e => {
  const b = e.target.closest(".chip"); if (!b) return;
  const s = SAMPLES[b.dataset.i];
  $("#urlIn").value = s.url; $("#brandIn").value = s.brand;
  runScan();
};

/* ---------- rate pill ---------- */
async function refreshRate() {
  try { state.rate = await (await api("/api/rate")).json(); state.rateAt = Date.now(); } catch { }
  drawRate();
}
function drawRate() {
  const r = state.rate; if (!r) return;
  const left = Math.max(0, r.reset_in_seconds - Math.floor((Date.now() - state.rateAt) / 1000));
  let remaining = r.remaining;
  if (r.used > 0 && left === 0) { refreshRate(); return; }
  const pill = $("#ratePill");
  pill.className = "pill" + (remaining === 0 ? " out" : remaining <= 2 ? " low" : "");
  $("#rateText").textContent = `${remaining}/${r.limit} Free Demo Scans Left This Hour` + (r.used > 0 ? ` · next slot ${fmtTime(left)}` : "");
}
setInterval(drawRate, 1000);
setInterval(refreshRate, 30000);

/* ---------- keys ---------- */
async function loadKeys() {
  const k = await (await api("/api/keys")).json();
  for (const n of ["gemini", "groq", "ip2whois"]) $("#s_" + n).textContent = k[n].set ? `Saved: ${k[n].masked}` : "Not set";
  const any = k.gemini.set || k.groq.set;
  $("#keyDot").className = "dot" + (any ? " ok" : "");
  $("#keyDot").title = any ? "AI key saved" : "No AI key — heuristic mode";
}
$("#keysBtn").onclick = () => { loadKeys(); $("#keysMsg").textContent = ""; openEl("keysModal"); };
$("#saveKeys").onclick = async () => {
  const body = {};
  for (const n of ["gemini", "groq", "ip2whois"]) { const v = $("#k_" + n).value.trim(); if (v) body[n] = v; }
  await api("/api/keys", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  ["gemini", "groq", "ip2whois"].forEach(n => $("#k_" + n).value = "");
  await loadKeys(); $("#keysMsg").textContent = "Saved.";
};
$("#clearKeys").onclick = async () => {
  await api("/api/keys", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ gemini: "", groq: "", ip2whois: "" }) });
  await loadKeys(); $("#keysMsg").textContent = "Stored keys cleared (keys in .env still apply).";
};

/* ---------- tracker ---------- */
function drawTracker(st = {}) {
  $("#tracker").innerHTML = NODES.map((t, i) => {
    const s = st[i + 1] || { status: "idle", summary: "Waiting" };
    const icon = { idle: "○", running: "◐", done: "●", warn: "▲", error: "✕" }[s.status];
    return `<div class="node ${s.status}"><div class="n">${icon} NODE ${i + 1}</div><div class="t">${esc(t)}</div><div class="s" title="${esc(s.summary || "")}">${esc(s.summary || (s.status === "running" ? "Running…" : "Waiting"))}</div></div>`;
  }).join("");
}
drawTracker();

/* ---------- scan ---------- */
$("#scanForm").onsubmit = e => { e.preventDefault(); runScan(); };
async function runScan() {
  if (state.busy) return;
  const url = $("#urlIn").value.trim(), brand = $("#brandIn").value.trim();
  toast(""); state.busy = true; $("#scanBtn").disabled = true;
  const st = {}; drawTracker(st); state.raw = []; renderLogs(null);
  const t0 = performance.now(); startTimer(t0);
  let failed = true;
  try {
    st[1] = { status: "running", summary: "Parsing…" }; drawTracker(st);
    const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, brand }) });
    if (r.status === 422) { const j = await r.json(); st[1] = { status: "error", summary: "Rejected" }; drawTracker(st); toast(j.detail); bannerMsg("Gatekeeper rejected input"); return; }
    if (r.status === 429) { const j = await r.json(); toast(j.detail, "warn"); drawTracker(); refreshRate(); return; }
    if (!r.ok) { toast("Server error " + r.status); drawTracker(); return; }
    const reader = r.body.getReader(), dec = new TextDecoder(); let buf = "";
    for (; ;) {
      const { done, value } = await reader.read(); if (done) break;
      buf += dec.decode(value, { stream: true });
      let i; while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1); if (!line) continue;
        state.raw.push(line); const ev = JSON.parse(line);
        if (ev.type === "start") bannerMsg("Pipeline running: " + ev.url);
        else if (ev.type === "node") { st[ev.n] = { status: ev.status, summary: ev.summary, ms: ev.ms }; drawTracker(st); if (ev.status === "running") bannerMsg("Node " + ev.n + ": " + NODES[ev.n - 1]); }
        else if (ev.type === "result") { state.scan = ev.result; failed = false; renderAll(); renderLogs(ev.result); }
        else if (ev.type === "error") toast(ev.detail);
      }
    }
  } catch (err) { toast("Request failed: " + err.message); }
  finally { stopTimer(t0, failed); state.busy = false; $("#scanBtn").disabled = false; refreshRate(); }
}

/* ---------- timer + logs ---------- */
function bannerMsg(m) { $("#bMsg").textContent = m; }
function startTimer(t0) {
  clearInterval(state.timer);
  $("#banner").className = "banner card run"; $("#bState").textContent = "RUNNING"; $("#bTimer").textContent = "0.0s";
  state.timer = setInterval(() => { $("#bTimer").textContent = ((performance.now() - t0) / 1000).toFixed(1) + "s"; }, 100);
}
function stopTimer(t0, failed) {
  clearInterval(state.timer);
  $("#bTimer").textContent = ((performance.now() - t0) / 1000).toFixed(1) + "s";
  $("#banner").className = "banner card " + (failed ? "fail" : "done"); $("#bState").textContent = failed ? "STOPPED" : "COMPLETE";
  if (!failed) bannerMsg("All 5 nodes complete");
}
function renderLogs(s) {
  const box = $("#logsBody");
  if (!s) { box.textContent = "Running…"; return; }
  const d = s.debug || { node_ms: {}, ai_attempts: [] };
  const nodeRows = NODES.map((t, i) => `<tr><td>Node ${i + 1}</td><td>${esc(t)}</td><td>${d.node_ms[i + 1] ?? "—"} ms</td></tr>`).join("");
  const att = (d.ai_attempts || []).map(a => `<tr><td>${esc(a.provider)}</td><td>${a.ok ? "OK" : "FAIL " + esc(a.error || "")}</td><td>${a.ms} ms</td></tr>`).join("") || `<tr><td colspan="3">No AI call made</td></tr>`;
  const prov = s.ai.ok ? esc(s.ai.provider) + (s.ai.fallback ? " (fallback)" : "") : "heuristic-engine (no AI)";
  box.innerHTML = `<h5>Per-node execution</h5><table><tr><th>#</th><th>Node</th><th>Time</th></tr>${nodeRows}</table>
    <h5>Probe latency</h5><table><tr><td>RDAP (rdap.org / ip2whois)</td><td>${d.rdap_ms} ms</td></tr><tr><td>TLS handshake :443</td><td>${d.tls_ms} ms</td></tr><tr><td>Total pipeline</td><td>${d.total_ms} ms</td></tr></table>
    <h5>Active AI provider: ${prov}</h5><table><tr><th>Provider / model</th><th>Result</th><th>Latency</th></tr>${att}</table>
    <h5>Raw NDJSON events</h5><pre>${esc(state.raw.map(l => l.length > 400 ? l.slice(0, 400) + " …(truncated)" : l).join("\n"))}</pre>`;
}

/* ---------- inspector ---------- */
function renderAll() { renderInspect(); renderIOC(); }
const gauge = (score, c) => {
  const R = 62, C = 2 * Math.PI * R;
  return `<div class="gauge"><svg width="150" height="150"><circle cx="75" cy="75" r="${R}" fill="none" stroke="#1F2937" stroke-width="12"/><circle cx="75" cy="75" r="${R}" fill="none" stroke="${c}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${C}" stroke-dashoffset="${C * (1 - score / 100)}"/></svg><div class="v"><b style="color:${c}">${score}</b><span>THREAT SCORE</span></div></div>`;
};
function sevOf(flags, part) { const m = flags.filter(f => f.part === part).map(f => f.sev); return m.includes("high") ? "high" : m.includes("med") ? "med" : m.includes("low") ? "low" : "ok"; }
function renderInspect() {
  const s = state.scan, an = s.anatomy, c = col(s.verdict);
  const seg = (lbl, val, part) => `<div class="seg ${sevOf(s.flags, part)}"><small>${lbl}</small><span>${esc(val || "—")}</span></div>`;
  const sub = an.subdomains.join(".");
  const pq = an.path + (an.query ? "?" + an.query : "");
  const rd = s.rdap, tl = s.tls;
  const ageTxt = rd.age_days != null ? `${rd.age_days} days` : "—";
  const stCls = x => ({ valid: "good", ok: "good", invalid: "bad", unregistered: "bad", no_dns: "bad" }[x] || (x === "skipped" ? "na" : "mid"));
  $("#view-inspect").innerHTML = `
  <div class="card hero ${s.verdict}">
    ${gauge(s.risk_score, c)}
    <div>
      <div class="verdict">${verdictLabel(s.verdict)}</div>
      <div class="badges">
        <span class="badge vec">${esc(s.attack_vector)}</span>
        ${s.impersonated_brand ? `<span class="badge brand">Impersonates: ${esc(s.impersonated_brand)}</span>` : ""}
        <span class="badge">engine: ${esc(s.ai.provider)}${s.ai.fallback ? " (fallback)" : ""}</span>
        <span class="badge">${s.duration_ms} ms</span>
      </div>
      <div class="mono" style="word-break:break-all;margin-bottom:8px">${esc(s.defanged)}</div>
      <div class="reason">${esc(s.ai.reasoning || "Deterministic engine verdict — add a Gemini or Groq key in “API Keys” for AI adversarial reasoning.")}
        ${s.ai.ok ? "" : `<small>AI unavailable: ${esc(s.ai.error || "no key configured")}</small>`}</div>
    </div>
  </div>
  <div class="card sec"><h3>URL Anatomy</h3>
    <div class="anat">
      ${seg("Scheme", an.scheme + "://", "scheme")}${seg("Subdomain", sub, "subdomain")}${seg("Root Domain", an.root_label || an.host, "domain")}${seg("TLD", an.tld ? "." + an.tld : "", "tld")}${seg("Path / Query", pq, "path")}
    </div>
    <ul class="flags">${s.flags.length ? s.flags.map(f => `<li><span class="sev ${f.sev}">${f.sev.toUpperCase()}</span><span>${esc(f.text)} <span class="muted mono">(+${f.pts})</span></span></li>`).join("") : '<li class="muted">No red flags raised.</li>'}</ul>
  </div>
  <div class="grid3" style="margin-top:14px">
    <div class="card tele"><h3>Lexical &amp; Entropy Signals</h3>
      <dl class="kv"><dt>Host label entropy</dt><dd>${an.host_entropy} bits</dd><dt>Query entropy</dt><dd>${an.query_entropy} bits</dd>
      <dt>Subdomain depth</dt><dd>${an.subdomains.length}</dd><dt>IP literal</dt><dd>${an.is_ip ? "YES" : "no"}</dd>
      <dt>@ redirect</dt><dd>${an.has_at_symbol ? "YES" : "no"}</dd><dt>Punycode</dt><dd>${an.has_punycode ? "YES" : "no"}</dd>
      <dt>Lure keywords</dt><dd>${esc(an.keywords.join(", ") || "none")}</dd><dt>Query params</dt><dd>${an.query_params.length}</dd></dl>
      <div class="bar"><i style="width:${Math.min(100, an.host_entropy / 4.5 * 100)}%;background:var(--cyan)"></i></div></div>
    <div class="card tele"><h3>Domain Age &amp; Registrar <span class="st ${stCls(rd.status)}">${esc(rd.status.toUpperCase())}</span></h3>
      <dl class="kv"><dt>Source</dt><dd>${esc(rd.source)}</dd><dt>Registrar</dt><dd>${esc(rd.registrar || "n/a")}</dd>
      <dt>Created</dt><dd>${esc((rd.created || "n/a").slice(0, 10))}</dd><dt>Age</dt><dd style="color:${rd.newly_registered ? "var(--bad)" : "inherit"}">${ageTxt}</dd>
      <dt>Expires</dt><dd>${esc((rd.expires || "n/a").slice(0, 10))}</dd><dt>Newly registered</dt><dd>${rd.newly_registered ? "YES (&lt;90d)" : "no"}</dd></dl>
      ${rd.detail ? `<p>${esc(rd.detail)}</p>` : ""}</div>
    <div class="card tele"><h3>TLS/SSL Certificate Audit <span class="st ${stCls(tl.status)}">${esc(tl.status.toUpperCase())}</span></h3>
      <dl class="kv"><dt>Issuer</dt><dd>${esc(tl.issuer || "n/a")}</dd><dt>Valid from</dt><dd>${esc(tl.valid_from || "n/a")}</dd>
      <dt>Expires</dt><dd>${esc(tl.valid_to || "n/a")}</dd><dt>Days remaining</dt><dd>${tl.days_remaining ?? "n/a"}</dd>
      <dt>SAN entries</dt><dd>${tl.san_count || 0}</dd><dt>Protocol</dt><dd>${esc(tl.tls_version || "n/a")}</dd>
      <dt>HTTPS enforced</dt><dd style="color:${tl.https_enforced ? "inherit" : "var(--bad)"}">${tl.https_enforced ? "yes" : "NO (http://)"}</dd>
      <dt>Self-signed / expired / mismatch</dt><dd>${[tl.self_signed, tl.expired, tl.hostname_mismatch].map(x => x ? "Y" : "n").join(" / ")}</dd></dl>
      <p>${esc(tl.detail || "")}</p></div>
  </div>`;
}

/* ---------- IOC report ---------- */
function renderIOC() {
  const s = state.scan, v = $("#view-ioc");
  if (!s) { v.innerHTML = `<div class="card empty">Run a scan to generate the SOC Threat Intelligence &amp; Takedown Brief.</div>`; return; }
  v.innerHTML = `
  <div class="ioc-bar"><button class="btn primary" id="copyIoc">Copy Defanged IOCs</button><button class="btn" id="dlRep">Download Threat Report (.md)</button><span id="copyMsg" class="muted small mono" style="align-self:center"></span></div>
  <div class="card report">
    <h2>SOC Threat Intelligence &amp; Takedown Brief</h2>
    <div class="mono small muted">${new Date(s.created_at * 1000).toUTCString()} · scan #${s.id}</div>
    <div class="verdict c-${s.verdict}" style="margin:10px 0;font:800 22px var(--sans)">${verdictLabel(s.verdict)} — ${s.risk_score}/100 · ${esc(s.attack_vector)}</div>
    <h4>Target (defanged)</h4><code class="ioc">${esc(s.defanged)}</code>
    <h4>Indicators of Compromise</h4>${s.soc.iocs.map(i => `<code class="ioc">${esc(i)}</code>`).join("")}
    <h4>Findings</h4><ul>${s.flags.map(f => `<li><b class="c-${f.sev === "high" ? "MALICIOUS" : f.sev === "med" ? "SUSPICIOUS" : ""}">[${f.sev.toUpperCase()}]</b> ${esc(f.text)}</li>`).join("") || "<li>None</li>"}</ul>
    <h4>Mitigation Steps</h4><ol>${s.soc.rules.map(r => `<li>${esc(r)}</li>`).join("")}</ol>
    ${s.soc.abuse_report ? `<h4>Abuse-Contact Report</h4><pre>${esc(s.soc.abuse_report)}</pre>` : ""}
  </div>`;
  $("#copyIoc").onclick = async () => {
    try { await navigator.clipboard.writeText(s.soc.iocs.join("\n")); $("#copyMsg").textContent = "Copied " + s.soc.iocs.length + " defanged IOCs ✓"; }
    catch { $("#copyMsg").textContent = "Clipboard blocked — select manually."; }
  };
  $("#dlRep").onclick = () => {
    const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([s.report_md], { type: "text/markdown" }));
    a.download = `phishradar-report-${s.id}.md`; a.click(); URL.revokeObjectURL(a.href);
  };
}
renderIOC();
$("#view-inspect").innerHTML = `<div class="card empty"><b>Awaiting target.</b><br>Paste a URL above or click a 1-click sample to start the 5-node pipeline.</div>`;

/* ---------- history ---------- */
async function loadHistory() {
  const rows = await (await api("/api/history")).json();
  $("#histList").innerHTML = rows.length ? rows.map(r => `<div class="hist" data-id="${r.id}"><div class="u">${esc(r.url)}</div><div class="m"><span class="c-${r.verdict}">${r.verdict} · ${r.score}</span><span>${new Date(r.created_at * 1000).toLocaleString()}</span></div></div>`).join("") : `<div class="empty">No scans yet.</div>`;
  return rows;
}
$("#histBtn").onclick = async () => { await loadHistory(); openEl("histDrawer"); };
$("#histList").onclick = async e => {
  const h = e.target.closest(".hist"); if (!h) return;
  state.scan = await (await api("/api/scans/" + h.dataset.id)).json();
  renderAll(); closeAll();
  document.querySelector('#tabs button[data-tab="inspect"]').click();
};

/* ---------- compare ---------- */
async function renderCompare() {
  const rows = await loadHistory(); const v = $("#view-compare");
  if (rows.length < 2) { v.innerHTML = `<div class="card empty">Scan at least two URLs to compare them side-by-side.</div>`; return; }
  const opts = sel => rows.map((r, i) => `<option value="${r.id}" ${i === sel ? "selected" : ""}>#${r.id} · ${r.verdict} ${r.score} · ${esc(r.url.slice(0, 60))}</option>`).join("");
  v.innerHTML = `<div class="card cmp-pick"><select id="selA">${opts(1)}</select><select id="selB">${opts(0)}</select></div><div class="card" style="margin-top:14px" id="cmpOut"></div>`;
  const go = async () => {
    const [a, b] = await Promise.all(["selA", "selB"].map(id => api("/api/scans/" + $("#" + id).value).then(r => r.json())));
    const row = (label, fa, fb, cmp) => {
      const A = fa(a), B = fb ? fb(b) : fa(b); let ca = "", cb = "";
      if (cmp) { const r = cmp(A, B); if (r > 0) { ca = "worse"; cb = "better"; } else if (r < 0) { ca = "better"; cb = "worse"; } }
      return `<tr><th>${label}</th><td class="${ca}">${esc(A)}</td><td class="${cb}">${esc(B)}</td></tr>`;
    };
    const num = x => (typeof x === "number" ? x : Infinity);
    $("#cmpOut").innerHTML = `<table class="cmp"><tr><th></th><td><b>#${a.id}</b> ${esc(a.defanged)}</td><td><b>#${b.id}</b> ${esc(b.defanged)}</td></tr>
      ${row("Verdict", x => x.verdict, null, (A, B) => ["SAFE", "SUSPICIOUS", "MALICIOUS"].indexOf(A) - ["SAFE", "SUSPICIOUS", "MALICIOUS"].indexOf(B))}
      ${row("Risk score", x => x.risk_score, null, (A, B) => A - B)}
      ${row("Attack vector", x => x.attack_vector)}${row("Impersonated brand", x => x.impersonated_brand || "—")}
      ${row("Scheme", x => x.anatomy.scheme, null, (A, B) => (A === "http") - (B === "http"))}
      ${row("TLS status", x => x.tls.status, null, (A, B) => (A !== "valid") - (B !== "valid"))}
      ${row("TLS issuer", x => x.tls.issuer || "n/a")}${row("Cert days remaining", x => x.tls.days_remaining ?? "n/a")}
      ${row("Domain age (days)", x => x.rdap.age_days ?? "unknown", null, (A, B) => num(B) - num(A) === 0 ? 0 : (num(A) < num(B) ? 1 : -1))}
      ${row("Registrar", x => x.rdap.registrar || "n/a")}
      ${row("Host entropy (bits)", x => x.anatomy.host_entropy)}${row("Query entropy (bits)", x => x.anatomy.query_entropy)}
      ${row("Red flags", x => x.flags.length, null, (A, B) => A - B)}
      ${row("Lexical red flags", x => x.flags.map(f => f.text).join(" • ") || "none")}</table>`;
  };
  $("#selA").onchange = $("#selB").onchange = go; go();
}

/* ---------- init ---------- */
refreshRate(); loadKeys();
