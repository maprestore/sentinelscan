function escape(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[character]));
}

function findingCard(item) {
  return `<article class="finding ${escape(item.severity)}"><div class="finding-head"><span class="badge">${escape(item.severity)}</span><strong>${escape(item.title)}</strong><span class="confidence">${escape(item.confidence || "unknown")} confidence</span></div><p>${escape(item.evidence)}</p><dl><dt>Location</dt><dd><a href="${escape(item.location)}">${escape(item.location)}</a></dd><dt>Category</dt><dd>${escape(item.category || "security-posture")}</dd><dt>Status</dt><dd>${escape(item.status || "observed")}</dd><dt>Fingerprint</dt><dd><code>${escape(item.fingerprint)}</code></dd></dl><div class="fix"><b>Next action</b><br>${escape(item.remediation)}</div></article>`;
}

function requestRow(item) {
  return `<tr><td>${escape(item.status ?? "-")}</td><td>${escape(item.elapsedMs ?? "-")} ms</td><td>${escape(item.bytesRead ?? "-")}</td><td>${escape(item.url)}</td>${item.redirectedTo ? `<td>redirects to ${escape(item.redirectedTo)}</td>` : "<td>-</td>"}</tr>`;
}

export function toHtml(report) {
  const findings = report.findings || [];
  const requests = report.requests || [];
  const paths = report.attackPaths || [];
  const totals = report.inventory?.totals || {};
  const summary = report.summary || {};
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SentinelScan report</title>
<style>
:root{color-scheme:dark;--bg:#081013;--panel:#101b20;--line:#24414a;--ink:#e8f5f2;--muted:#8ca6a8;--cyan:#55e6ef;--green:#b8ff4e;--pink:#ff6eaa;--orange:#ffbd5a}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% 0,#153b45 0,#081013 42%);color:var(--ink);font:14px/1.55 system-ui,sans-serif}main{max-width:1180px;margin:auto;padding:32px 20px 70px}header{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;border-bottom:1px solid var(--line);padding-bottom:24px}h1{margin:0;font-size:clamp(28px,5vw,58px);letter-spacing:-.05em}h2{margin:0 0 14px;font-size:18px}.eyebrow,.label{color:var(--cyan);font:11px/1.2 ui-monospace,monospace;letter-spacing:.13em;text-transform:uppercase}.target{margin-top:10px;color:var(--muted);overflow-wrap:anywhere}.risk{min-width:130px;padding:16px;border:1px solid var(--green);text-align:center}.risk b{display:block;color:var(--green);font-size:34px}.risk span{color:var(--muted);font:11px ui-monospace,monospace}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:22px 0}.stat,.panel{border:1px solid var(--line);background:rgba(16,27,32,.86);padding:16px}.stat b{display:block;font-size:24px;color:var(--cyan)}.stat span{color:var(--muted);font-size:12px}.panel{margin-top:14px}.finding{border:1px solid var(--line);border-left:4px solid var(--muted);background:#0c171b;margin:10px 0;padding:14px}.finding.high{border-left-color:#ff658c}.finding.medium{border-left-color:var(--orange)}.finding.low{border-left-color:var(--cyan)}.finding.info{border-left-color:var(--green)}.finding-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.finding-head strong{font-size:16px}.badge{border:1px solid currentColor;padding:2px 7px;font:11px ui-monospace,monospace;text-transform:uppercase}.confidence{margin-left:auto;color:var(--muted);font:11px ui-monospace,monospace}.finding p{color:var(--muted);margin:10px 0}.finding dl{display:grid;grid-template-columns:100px 1fr;gap:3px 10px;margin:10px 0;font-size:12px}.finding dt{color:var(--muted)}.finding dd{margin:0;overflow-wrap:anywhere}.finding a{color:var(--cyan)}.fix{border-top:1px solid var(--line);padding-top:10px;color:#d8e9e7}.path{border-left:3px solid var(--pink);padding:10px 12px;margin:10px 0;background:rgba(255,110,170,.06)}.path strong{color:var(--pink)}table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;border-bottom:1px solid var(--line);padding:8px;vertical-align:top}th{color:var(--cyan);font:11px ui-monospace,monospace;text-transform:uppercase}td:last-child{overflow-wrap:anywhere;color:var(--muted)}code{color:var(--green)}@media(max-width:700px){.grid{grid-template-columns:repeat(2,1fr)}header{display:block}.risk{margin-top:18px}.confidence{margin-left:0}}@media(max-width:430px){.grid{grid-template-columns:1fr 1fr}.finding dl{grid-template-columns:80px 1fr}main{padding:22px 12px 50px}}
</style></head><body><main>
<header><div><div class="eyebrow">SENTINELSCAN / AUTHORIZED POSTURE REPORT</div><h1>Evidence, not noise.</h1><div class="target">${escape(report.target)}<br>Completed ${escape(report.finishedAt || "-")}</div></div><div class="risk"><b>${escape(report.risk?.score ?? "-")}</b><span>RISK / ${escape(report.risk?.grade || "-")}</span></div></header>
<section class="grid"><div class="stat"><b>${escape(summary.pagesScanned ?? 0)}</b><span>HTML pages</span></div><div class="stat"><b>${escape(summary.resourcesScanned ?? 0)}</b><span>resources</span></div><div class="stat"><b>${escape(summary.requestsMade ?? requests.length)}</b><span>GET requests</span></div><div class="stat"><b>${escape(summary.findings ?? findings.length)}</b><span>findings</span></div></section>
<section class="panel"><div class="label">Execution</div><p>Termination: <strong>${escape(summary.termination || "-")}</strong> · Elapsed: <strong>${escape(summary.elapsedMs ?? "-")} ms</strong> · Confidence: <strong>${escape(JSON.stringify(summary.byConfidence || {}))}</strong></p></section>
<section class="panel"><div class="label">Correlated attack paths</div>${paths.length ? paths.map((path) => `<div class="path"><strong>${escape(path.severity)} / ${escape(path.title)}</strong><p>${escape(path.whyItMatters)}</p><div>${escape(path.nextAction)}</div></div>`).join("") : "<p>No correlated attack paths were built.</p>"}</section>
<section class="panel"><div class="label">Findings / ${findings.length}</div>${findings.length ? findings.map(findingCard).join("") : "<p>No findings were recorded.</p>"}</section>
<section class="panel"><div class="label">Inventory</div><p>Forms: ${escape(totals.forms || 0)} · Password forms: ${escape(totals.passwordForms || 0)} · Scripts: ${escape(totals.scripts || 0)} · Client API endpoints: ${escape(totals.clientApiEndpoints?.length || 0)}</p></section>
<section class="panel"><div class="label">Request evidence</div><div style="overflow:auto"><table><thead><tr><th>Status</th><th>Time</th><th>Bytes</th><th>URL</th><th>Redirect</th></tr></thead><tbody>${requests.length ? requests.map(requestRow).join("") : '<tr><td colspan="5">No request evidence was recorded.</td></tr>'}</tbody></table></div></section>
<p style="color:var(--muted);font-size:12px;margin-top:24px">Safe GET-only observation report. Findings are review leads, not proof of exploitability. Keep this file private when it contains internal URLs or evidence.</p>
</main></body></html>`;
}
