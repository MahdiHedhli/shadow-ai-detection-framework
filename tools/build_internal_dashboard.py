#!/usr/bin/env python3
"""Build a private, filterable multi-client Shadow AI technician dashboard.

The dashboard embeds validated client telemetry. Keep its manifest, archives,
and output in an access-controlled private location outside this repository.
Customer CSV export is available only after selecting exactly one client.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import build_dashboard_feed
import build_report


ROOT = Path(__file__).resolve().parents[1]


def build_payload(
    manifest_path: Path,
    period: str | None,
    import_note: str | None = None,
    incomplete_client_ids: list[str] | None = None,
) -> dict[str, Any]:
    clients = build_dashboard_feed.load_manifest(manifest_path)
    providers, indicator_products = build_report.load_provider_names()
    findings: list[dict[str, Any]] = []
    scans: list[dict[str, Any]] = []
    for client in clients:
        client_findings, client_scans = build_dashboard_feed.load_client_data(
            client, period, providers, indicator_products
        )
        findings.extend(client_findings)
        scans.extend(client_scans)
    # The technician view is a present-state inventory: keep only each
    # endpoint's latest scan, even though the private archive is append-only.
    # A latest partial scan remains partial; never backfill older findings.
    latest_scans: dict[tuple[str, str], dict[str, Any]] = {}
    no_observation_scans: list[dict[str, Any]] = []
    for row in scans:
        endpoint_key = row.get("_endpoint_key")
        if not endpoint_key:
            no_observation_scans.append(row)
            continue
        key = (row["client_id"], endpoint_key)
        previous = latest_scans.get(key)
        candidate_time = datetime.fromisoformat(row["collected_at"].replace("Z", "+00:00"))
        previous_time = (
            datetime.fromisoformat(previous["collected_at"].replace("Z", "+00:00"))
            if previous else None
        )
        if previous is None or (candidate_time, row["_observation_id"]) > (
            previous_time, previous["_observation_id"]
        ):
            latest_scans[key] = row

    scans = [*latest_scans.values(), *no_observation_scans]
    latest_observations = {
        (row["client_id"], row["_observation_id"])
        for row in latest_scans.values()
    }
    findings = [
        row for row in findings
        if (row["client_id"], row["observation_id"]) in latest_observations
    ]
    for row in scans:
        row.pop("_endpoint_key", None)
        row.pop("_observation_id", None)

    findings.sort(key=lambda row: (
        row["client_label"].casefold(), row["observed_at"], row["provider_name"].casefold()
    ))
    scans.sort(key=lambda row: (row["client_label"].casefold(), row["collected_at"]))
    return {
        "schema_version": "1.0",
        "refreshed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "period": f"latest scan per endpoint{f' in {period}' if period else ''}",
        "import_note": import_note or "",
        "incomplete_client_ids": sorted(set(incomplete_client_ids or [])),
        "clients": [{"client_id": c["client_id"], "client_label": c["client_label"]} for c in clients],
        "findings": findings,
        "scans": scans,
    }


def write_dashboard(path: Path, content: str, overwrite: bool) -> Path:
    path = build_dashboard_feed.outside_public_repo(path, "dashboard output")
    parent = build_dashboard_feed.ensure_private_directory(path.parent, "dashboard output directory")
    if path.exists() and not overwrite:
        raise build_dashboard_feed.FeedError(
            "dashboard output already exists; pass --overwrite only when replacing it is intended"
        )
    descriptor, temporary = tempfile.mkstemp(prefix=".shadow-ai-dashboard-", suffix=".tmp", dir=parent)
    staged = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists() and not overwrite:
            raise build_dashboard_feed.FeedError(
                "dashboard output appeared during export; it was not replaced"
            )
        os.replace(staged, path)
    finally:
        staged.unlink(missing_ok=True)
    return path


def make_html(payload: dict[str, Any]) -> str:
    safe_payload = build_report.safe_json_for_html(payload)
    return DASHBOARD_HTML.replace("{{DASHBOARD_DATA}}", safe_payload)


DASHBOARD_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>Shadow AI | Technician dashboard</title>
<style>
:root{color-scheme:light;--ink:#172b4d;--muted:#63738a;--line:#dfe6ef;--paper:#f4f7fb;--card:#fff;--blue:#245fbd;--blue-soft:#eaf1fd;--green:#237a62;--amber:#9b5b00;--red:#a33b43;--shadow:0 5px 20px #172b4d0b}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.45 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1440px;margin:auto;padding:28px 30px 42px}.top{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;margin-bottom:22px}.eyebrow{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--blue);font-weight:800}.top h1{font-size:27px;line-height:1.15;margin:5px 0 7px;letter-spacing:-.03em}.lede{color:var(--muted);margin:0;max-width:720px}.badge-note{background:#fff;border:1px solid var(--line);border-radius:12px;padding:10px 13px;color:var(--muted);font-size:12px;max-width:280px}.badge-note strong{color:var(--ink)}.filters,.panel,.kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}.filters{padding:15px;display:grid;grid-template-columns:repeat(6,minmax(125px,1fr));gap:10px;margin-bottom:15px}.field label{display:block;font-weight:700;color:#465975;font-size:11px;margin:0 0 5px}.field input,.field select{width:100%;height:37px;border:1px solid #cbd5e2;border-radius:8px;padding:0 9px;background:#fff;color:var(--ink);font:inherit}.field input:focus,.field select:focus,button:focus-visible,th button:focus-visible{outline:3px solid #80aef5;outline-offset:1px}.hide-wrap{display:flex;align-items:center;gap:7px;margin-top:21px;color:#465975}.hide-wrap input{width:16px;height:16px;accent-color:var(--blue)}.filter-actions{display:flex;justify-content:flex-end;gap:8px;align-items:end}.btn{height:37px;border:1px solid #cbd5e2;border-radius:8px;background:#fff;color:var(--ink);padding:0 12px;font:inherit;font-weight:700;cursor:pointer}.btn.primary{background:var(--blue);border-color:var(--blue);color:#fff}.btn:disabled{opacity:.45;cursor:not-allowed}.scope-hint{grid-column:1/-1;margin:0;color:var(--muted);font-size:12px}.grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin:0 0 15px}.kpi{padding:15px 17px}.kpi .label{font-size:12px;color:var(--muted);font-weight:700}.kpi .value{font-size:26px;font-weight:800;letter-spacing:-.035em;margin-top:5px}.kpi .value.timestamp{font-size:17px;letter-spacing:-.02em;line-height:1.3}.kpi .sub{font-size:11px;color:var(--muted);margin-top:3px}.charts{display:grid;grid-template-columns:1.1fr 1fr 1fr;gap:12px;margin:0 0 15px}.panel{padding:17px;min-width:0}.panel h2{font-size:15px;margin:0 0 3px;letter-spacing:-.01em}.panel .intro{font-size:11px;color:var(--muted);margin:0 0 13px}.bars{display:grid;gap:9px}.bar{display:grid;grid-template-columns:minmax(70px,1fr) 1.3fr 35px;align-items:center;gap:9px;font-size:11px}.bar .name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.track{height:9px;background:#edf1f6;border-radius:9px;overflow:hidden}.fill{height:100%;background:linear-gradient(90deg,#3984e5,#74a7f3);border-radius:9px}.bar .num{text-align:right;font-variant-numeric:tabular-nums;font-weight:800}.empty{color:var(--muted);font-size:12px;padding:12px 0}.table-head{display:flex;justify-content:space-between;align-items:flex-end;gap:12px;margin:0 0 12px}.table-head h2{margin:0;font-size:16px}.count{color:var(--muted);font-size:12px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:10px}table{border-collapse:collapse;width:100%;min-width:1000px;background:#fff}thead th{background:#f7f9fc;color:#4e607b;font-size:11px;letter-spacing:.02em;text-align:left;white-space:nowrap;position:sticky;top:0;z-index:1}th,td{padding:10px 11px;border-bottom:1px solid #e8edf3;vertical-align:top}th button{border:0;background:transparent;color:inherit;font:inherit;font-weight:800;cursor:pointer;padding:0;text-align:left}tbody tr:hover{background:#f8fbff}.muted{color:var(--muted);font-size:11px;display:block}.pill{display:inline-flex;border-radius:99px;padding:3px 8px;font-size:10px;font-weight:800;text-transform:capitalize;background:#eef2f7;color:#495a70}.pill.high{background:#e9f6ef;color:var(--green)}.pill.medium{background:#fff4db;color:var(--amber)}.pill.low{background:#fdeced;color:var(--red)}.pill.acknowledged{background:#edf2ff;color:#425aaf}.pill.justified{background:#e9f6ef;color:var(--green)}.callout{border-left:3px solid #e5a642;padding:9px 12px;background:#fff9ed;color:#6b4c1c;font-size:12px;margin:0 0 14px;border-radius:0 8px 8px 0}.none{padding:30px;text-align:center;color:var(--muted)}footer{color:var(--muted);font-size:11px;margin-top:15px}.sr{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.pager{display:flex;justify-content:space-between;align-items:center;gap:12px;padding-top:10px;color:var(--muted);font-size:12px}.pager-actions{display:flex;gap:7px}
.filter-actions{grid-column:span 2}.filter-actions .btn{white-space:nowrap}
.charts{grid-template-columns:repeat(4,minmax(0,1fr))}
.client-table-wrap{max-height:440px;overflow:auto;border:1px solid var(--line);border-radius:10px}.client-table-wrap table{min-width:880px}.client-table-wrap th{position:sticky;top:0;z-index:1}
@media(max-width:1050px){.filters{grid-template-columns:repeat(3,minmax(120px,1fr))}.grid{grid-template-columns:repeat(3,minmax(0,1fr))}.charts{grid-template-columns:1fr 1fr}.charts .panel:first-child{grid-column:1/-1}}@media(max-width:700px){main{padding:18px 12px 30px}.top{display:block}.badge-note{margin-top:12px;max-width:none}.filters{grid-template-columns:repeat(2,minmax(0,1fr))}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.charts{grid-template-columns:1fr}.charts .panel:first-child{grid-column:auto}.filter-actions{grid-column:1/-1}}
</style></head>
<body><main>
<header class="top"><div><div class="eyebrow">RampUp · AI Enablement</div><h1>Shadow AI inventory</h1><p class="lede" id="lede"></p></div><div class="badge-note"><strong>Internal technician view</strong><br><span id="refreshTimestamp"></span><br>Contains cross-client detection metadata. Keep this file in an approved, access-controlled location. It makes no network requests.</div></header>
<p class="callout" id="importNotice" hidden></p>
<section class="filters" aria-label="Dashboard filters">
<div class="field"><label for="client">Client</label><select id="client"><option value="">All clients</option></select></div>
<div class="field"><label for="provider">Provider / product</label><select id="provider"><option value="">All providers/products</option></select></div>
<div class="field"><label for="category">Finding type</label><select id="category"><option value="">All finding types</option></select></div>
<div class="field"><label for="confidence">Confidence</label><select id="confidence"><option value="">All confidence levels</option><option>high</option><option>medium</option><option>low</option></select></div>
<div class="field"><label for="review">Review state</label><select id="review"><option value="">All review states</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="justified">Justified</option></select></div>
<div class="field"><label for="search">Search evidence</label><input id="search" type="search" placeholder="Domain, extension ID…" autocomplete="off"></div>
<label class="hide-wrap"><input id="hideReviewed" type="checkbox"> Hide acknowledged / justified</label>
<div class="field"><label for="sortDirection">Sort order</label><select id="sortDirection"><option value="asc">Ascending</option><option value="desc">Descending</option></select></div>
<div class="filter-actions"><button class="btn" id="reset" type="button">Reset</button><button class="btn" id="exportReport" type="button" disabled>Export client report</button><button class="btn primary" id="export" type="button" disabled>Export client CSV</button></div>
<p class="scope-hint" id="scopeHint"></p>
</section>
<p class="callout">This view uses each endpoint's latest validated scan; a missing signal is not proof of no AI use. Scan status is scanner-reported for represented endpoints, not total fleet coverage. Source-export truncation is flagged separately above.</p>
<section class="grid" aria-label="Filtered summary">
<article class="kpi"><div class="label">Newest scan record (UTC)</div><div class="value timestamp" id="kLastScan">—</div><div class="sub" id="kLastScanSub">No scan data loaded</div></article>
<article class="kpi"><div class="label">Clients represented</div><div class="value" id="kClients">—</div><div class="sub">Clients with a latest scan record</div></article>
<article class="kpi"><div class="label">Endpoints with latest scans</div><div class="value" id="kScans">—</div><div class="sub" id="kScanSub"></div></article>
<article class="kpi"><div class="label">Current finding observations</div><div class="value" id="kFindings">—</div><div class="sub">Findings in each endpoint's latest scan</div></article>
<article class="kpi"><div class="label">Open review</div><div class="value" id="kOpen">—</div><div class="sub">Current findings not acknowledged or justified</div></article>
</section>
<section class="charts" aria-label="Filtered breakdowns">
<article class="panel"><h2>Current findings by client</h2><p class="intro">Latest scan per endpoint, with active finding filters</p><div class="bars" id="byClient"></div></article>
<article class="panel"><h2>By provider</h2><p class="intro">Findings in the filtered current-state view</p><div class="bars" id="byProvider"></div></article>
<article class="panel"><h2>Collector scan status</h2><p class="intro">Scanner-reported status for represented endpoints; export quality is shown separately</p><div class="bars" id="coverage"></div></article>
<article class="panel"><h2>Collector versions</h2><p class="intro">Version on each endpoint’s latest scan</p><div class="bars" id="collectorVersions"></div></article>
</section>
<section class="panel" style="margin-bottom:15px"><div class="table-head"><div><h2>Client comparison</h2><p class="intro" style="margin:3px 0 0">Click a heading to sort clients or values. Finding counts honor active finding filters.</p></div><div class="count" id="clientCount"></div></div>
<div class="client-table-wrap"><table><thead><tr>
<th scope="col"><button data-client-sort="client_label">Client <span></span></button></th><th scope="col"><button data-client-sort="finding_observations">Current finding observations <span></span></button></th><th scope="col"><button data-client-sort="distinct_findings">Distinct finding keys <span></span></button></th><th scope="col"><button data-client-sort="open_review">Open review findings <span></span></button></th><th scope="col"><button data-client-sort="endpoints_scanned">Endpoints with latest scans <span></span></button></th><th scope="col"><button data-client-sort="partial_scans">Partial latest scans <span></span></button></th><th scope="col"><button data-client-sort="no_observations">No-observation archives <span></span></button></th><th scope="col"><button data-client-sort="oldest_latest_scan_at">Oldest latest scan (UTC) <span></span></button></th>
</tr></thead><tbody id="clientRows"></tbody></table></div></section>
<section class="panel"><div class="table-head"><div><h2>Finding observations</h2><p class="intro" style="margin:3px 0 0">Select a single client before exporting. Click a column heading to sort.</p></div><div class="count" id="count"></div></div>
<div class="table-wrap"><table><thead><tr>
<th scope="col"><button data-sort="client_label">Client <span></span></button></th><th scope="col"><button data-sort="observed_at">Observed (UTC) <span></span></button></th><th scope="col"><button data-sort="provider_name">Provider / product <span></span></button></th><th scope="col"><button data-sort="category">Finding type <span></span></button></th><th scope="col"><button data-sort="confidence_rank">Confidence <span></span></button></th><th scope="col"><button data-sort="evidence_level">Evidence <span></span></button></th><th scope="col"><button data-sort="review_status">Review <span></span></button></th><th scope="col">Browser / evidence detail</th>
</tr></thead><tbody id="rows"></tbody></table><div class="none" id="empty" hidden>No finding observations match this view. Check scan coverage before interpreting an empty result.</div></div>
<div class="pager"><span id="pageInfo"></span><div class="pager-actions"><button class="btn" id="prevPage" type="button">Previous</button><button class="btn" id="nextPage" type="button">Next</button></div></div>
</section><footer id="footer"></footer>
</main><script>
"use strict";
const data={{DASHBOARD_DATA}};
const $=id=>document.getElementById(id);
const incompleteClientIds=new Set(data.incomplete_client_ids||[]);
$("exportReport").addEventListener("click",exportClientReport);
$("refreshTimestamp").textContent=data.refreshed_at?`Dashboard rebuilt ${new Intl.DateTimeFormat(undefined,{dateStyle:"medium",timeStyle:"short",timeZone:"UTC"}).format(new Date(data.refreshed_at))} UTC`:"Dashboard build time unavailable";
if(data.import_note){const affected=data.clients.filter(c=>incompleteClientIds.has(c.client_id)).map(c=>c.client_label);$("importNotice").textContent=data.import_note+(affected.length?` Affected client(s): ${affected.join(", ")}.`:" Affected client could not be mapped.");$("importNotice").hidden=false}
const state={sort:"observed_at",direction:"desc",page:0,pageSize:250};
const clientSort={key:"finding_observations",direction:"desc"};
const labelCategory=value=>String(value||"").replaceAll("_"," ");
function option(select,value,label){const item=document.createElement("option");item.value=value;item.textContent=label;select.append(item)}
function addOptions(id,values,labeler=x=>x){const select=$(id);for(const value of [...new Set(values.filter(Boolean))].sort((a,b)=>String(labeler(a)).localeCompare(String(labeler(b)))))option(select,value,labeler(value))}
for(const item of data.clients)option($("client"),item.client_id,item.client_label);
const products=new Map();for(const r of data.findings)products.set(`${r.provider_id}|${r.product}`,`${r.provider_name} · ${r.product}`);addOptions("provider",[...products.keys()],k=>products.get(k));
addOptions("category",data.findings.map(r=>r.category),labelCategory);
const safeText=row=>[row.client_label,row.provider_name,row.product,row.category,row.capability,row.browser,row.matched_domain,row.extension_id,row.display_name,row.version,row.classification_basis,row.evidence_level].join(" ").toLocaleLowerCase();
function filteredFindings(){const client=$("client").value,provider=$("provider").value,category=$("category").value,confidence=$("confidence").value,review=$("review").value,query=$("search").value.trim().toLocaleLowerCase(),hide=$("hideReviewed").checked;return data.findings.filter(r=>{if(client&&r.client_id!==client)return false;if(provider&&`${r.provider_id}|${r.product}`!==provider)return false;if(category&&r.category!==category)return false;if(confidence&&r.confidence!==confidence)return false;if(review&&r.review_status!==review)return false;if(hide&&r.review_status!=="open")return false;if(query&&!safeText(r).includes(query))return false;return true})}
function filteredScans(){const client=$("client").value;return data.scans.filter(r=>!client||r.client_id===client)}
function barList(id,counts){const root=$(id);root.replaceChildren();const items=[...counts.entries()].sort((a,b)=>b[1]-a[1]||String(a[0]).localeCompare(String(b[0]))).slice(0,8),max=Math.max(1,...items.map(x=>x[1]));if(!items.length){const e=document.createElement("div");e.className="empty";e.textContent="No data in this view.";root.append(e);return}for(const [name,count] of items){const line=document.createElement("div");line.className="bar";const text=document.createElement("span");text.className="name";text.textContent=name;const track=document.createElement("div");track.className="track";const fill=document.createElement("div");fill.className="fill";fill.style.width=`${Math.max(2,count/max*100)}%`;track.append(fill);const value=document.createElement("span");value.className="num";value.textContent=count.toLocaleString();line.append(text,track,value);root.append(line)}}
function sortValue(row,key){if(key==="provider_name")return `${row.provider_name} ${row.product}`.toLocaleLowerCase();if(key==="confidence_rank"||key==="evidence_level")return Number(row[key]||0);if(key==="category"||key==="review_status"||key==="client_label")return String(row[key]||"").toLocaleLowerCase();return String(row[key]||"")}
function sortedRows(source){const direction=$("sortDirection").value;return [...source].sort((a,b)=>{const x=sortValue(a,state.sort),y=sortValue(b,state.sort);const cmp=typeof x==="number"&&typeof y==="number"?x-y:String(x).localeCompare(String(y),undefined,{numeric:true});return (direction==="desc"?-1:1)*cmp||a.client_id.localeCompare(b.client_id)||a.finding_id.localeCompare(b.finding_id)})}
function renderClientComparison(findings,scans){const selected=$("client").value;const rows=data.clients.filter(c=>!selected||c.client_id===selected).map(client=>{const cf=findings.filter(r=>r.client_id===client.client_id),cs=scans.filter(r=>r.client_id===client.client_id),dated=cs.filter(s=>(s.scan_status==="complete"||s.scan_status==="partial")&&Number.isFinite(Date.parse(s.collected_at))).map(s=>s.collected_at).sort();return {client_id:client.client_id,client_label:client.client_label,finding_observations:cf.length,distinct_findings:new Set(cf.map(r=>r.finding_key)).size,open_review:cf.filter(r=>r.review_status==="open").length,endpoints_scanned:cs.filter(r=>r.scan_status==="complete"||r.scan_status==="partial").length,partial_scans:cs.filter(r=>r.scan_status==="partial").length,no_observations:cs.filter(r=>r.scan_status==="no_observations").length,oldest_latest_scan_at:dated[0]||""}});rows.sort((a,b)=>{const x=a[clientSort.key],y=b[clientSort.key];let cmp;if(clientSort.key==="oldest_latest_scan_at"){if(!x||!y)return x? -1:y?1:a.client_label.localeCompare(b.client_label);cmp=Date.parse(x)-Date.parse(y)}else cmp=typeof x==="number"?x-y:String(x).localeCompare(String(y),undefined,{numeric:true});return (clientSort.direction==="desc"?-1:1)*cmp||a.client_label.localeCompare(b.client_label)});$("clientCount").textContent=`${rows.length.toLocaleString()} clients`;const body=$("clientRows");body.replaceChildren();for(const row of rows){const tr=document.createElement("tr");for(const key of ["client_label","finding_observations","distinct_findings","open_review","endpoints_scanned","partial_scans","no_observations","oldest_latest_scan_at"]){const td=document.createElement("td");if(key==="client_label")td.textContent=row[key];else if(key==="oldest_latest_scan_at")td.textContent=row[key]?`${new Intl.DateTimeFormat(undefined,{dateStyle:"medium",timeStyle:"short",timeZone:"UTC"}).format(new Date(row[key]))} UTC`:"No scan timestamp";else td.textContent=row[key].toLocaleString();tr.append(td)}body.append(tr)}for(const button of document.querySelectorAll("th button[data-client-sort]")){const active=button.dataset.clientSort===clientSort.key;button.querySelector("span").textContent=active?(clientSort.direction==="asc"?"▲":"▼"):"";button.setAttribute("aria-sort",active?(clientSort.direction==="asc"?"ascending":"descending"):"none")}}
function render(){const all=filteredFindings(),scans=filteredScans(),direction=$("sortDirection").value;const rows=sortedRows(all),start=state.page*state.pageSize,shown=rows.slice(start,start+state.pageSize);
const clients=new Set(scans.filter(s=>s.scan_status!=="no_observations").map(s=>s.client_id));const completed=scans.filter(s=>s.scan_status==="complete").length,partial=scans.filter(s=>s.scan_status==="partial").length,noObs=scans.filter(s=>s.scan_status==="no_observations").length;const open=all.filter(r=>r.review_status==="open").length;
const newest=scans.filter(s=>s.collected_at&&Number.isFinite(Date.parse(s.collected_at))).sort((a,b)=>Date.parse(b.collected_at)-Date.parse(a.collected_at))[0];$("kLastScan").textContent=newest?`${new Intl.DateTimeFormat(undefined,{dateStyle:"medium",timeStyle:"short",timeZone:"UTC"}).format(new Date(newest.collected_at))} UTC`:"No scan data";$("kLastScanSub").textContent=newest?`${newest.scan_status} · ${$("client").value?"selected client":"all clients"}`:"No scan timestamp is available in this scope";
$("kClients").textContent=clients.size.toLocaleString();$("kScans").textContent=(completed+partial).toLocaleString();$("kScanSub").textContent=`${completed} complete · ${partial} partial · ${noObs} clients with no observations`;$("kFindings").textContent=all.length.toLocaleString();$("kOpen").textContent=open.toLocaleString();$("count").textContent=`${rows.length.toLocaleString()} current finding observations`;
const byClient=new Map(),byProvider=new Map(),coverage=new Map(),collectorVersions=new Map();for(const r of all)byClient.set(r.client_label,(byClient.get(r.client_label)||0)+1);for(const r of all){const name=r.provider_name||r.provider_id;byProvider.set(name,(byProvider.get(name)||0)+1)}for(const r of scans){const name=r.client_label;const value=coverage.get(name)||{complete:0,partial:0,no_observations:0};if(r.scan_status in value)value[r.scan_status]+=1;coverage.set(name,value);if(r.scan_status==="complete"||r.scan_status==="partial"){const version=r.collector_version||"Unknown";collectorVersions.set(version,(collectorVersions.get(version)||0)+1)}}
barList("byClient",byClient);barList("byProvider",byProvider);barList("coverage",new Map([...coverage].map(([name,v])=>[`${name} · ${v.complete} complete / ${v.partial} partial / ${v.no_observations} no data`,v.complete+v.partial+v.no_observations])));barList("collectorVersions",collectorVersions);
renderClientComparison(all,scans);
const body=$("rows");body.replaceChildren();$("empty").hidden=rows.length!==0;for(const r of shown){const tr=document.createElement("tr");const observed=r.observed_at||r.collected_at;const observedLabel=observed?`${new Intl.DateTimeFormat(undefined,{dateStyle:"medium",timeStyle:"short",timeZone:"UTC"}).format(new Date(observed))} UTC`:"—";const values=[r.client_label,observedLabel,`${r.provider_name} · ${r.product}`,labelCategory(r.category),r.confidence,r.evidence_level,r.review_status];for(let i=0;i<values.length;i++){const td=document.createElement("td");td.textContent=values[i]||"—";if(i===4||i===6){const pill=document.createElement("span");pill.className=`pill ${i===4?r.confidence:r.review_status}`;pill.textContent=values[i]||"—";td.replaceChildren(pill)}tr.append(td)}const detail=document.createElement("td");const bits=[r.browser,r.matched_domain,r.extension_id,r.display_name,r.version,r.classification_basis].filter(Boolean);detail.textContent=bits.join(" · ")||"—";tr.append(detail);body.append(tr)}
const pageCount=Math.ceil(rows.length/state.pageSize);$("pageInfo").textContent=rows.length?`Rows ${start+1}–${Math.min(start+state.pageSize,rows.length)} of ${rows.length.toLocaleString()} · Export includes all filtered rows for the selected client.`:"No rows to show";$("prevPage").disabled=state.page===0;$("nextPage").disabled=pageCount===0||state.page>=pageCount-1;
$("export").disabled=!$("client").value;$("exportReport").disabled=!$("client").value;$("scopeHint").textContent=$("client").value?`Exports contain only the selected client's currently filtered ${all.length.toLocaleString()} finding observations; endpoint and local-user identities and reviewer notes are not included. Browser downloads use local default permissions—secure the file before sharing or retaining it.`:"Customer exports are disabled for the all-client view. Select one client to export only that client's filtered findings.";
for(const button of document.querySelectorAll("th button[data-sort]")){const active=button.dataset.sort===state.sort;button.querySelector("span").textContent=active?(direction==="asc"?"▲":"▼"):"";button.setAttribute("aria-sort",active?(direction==="asc"?"ascending":"descending"):"none")}}
function csvCell(value){let text=String(value??"");if(/^[\s\u0000-\u001f]*[=+\-@]/.test(text))text="'"+text;return `"${text.replaceAll('"','""')}"`}
function exportClient(){
  const clientId=$("client").value;
  if(!clientId)return;
  const client=data.clients.find(c=>c.client_id===clientId);
  if(!client)return;
  const rows=sortedRows(filteredFindings().filter(r=>r.client_id===clientId));
  const fields=["client_label","observed_at","collected_at","os_family","provider_name","product","category","capability","confidence","evidence_level","review_status","reviewed_at","browser","matched_domain","extension_id","display_name","version","classification_basis","source_export_quality"];
  const quality=incompleteClientIds.has(clientId)?"incomplete_truncated_scanner_result_excluded":"no_truncated_result_attributed_in_export";
  const csv=[fields.map(csvCell).join(","),...rows.map(r=>fields.map(f=>csvCell(f==="source_export_quality"?quality:r[f])).join(","))].join("\r\n")+"\r\n";
  const blob=new Blob([csv],{type:"text/csv;charset=utf-8"}),url=URL.createObjectURL(blob),a=document.createElement("a");
  a.href=url;a.download=`shadow-ai-${clientId}-current-state.csv`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)
}
function reportCell(value){return String(value??"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#39;")}
function exportClientReport(){const clientId=$("client").value;if(!clientId)return;const client=data.clients.find(c=>c.client_id===clientId);if(!client)return;const rows=sortedRows(filteredFindings().filter(r=>r.client_id===clientId)),scans=filteredScans().filter(r=>r.client_id===clientId),providers=new Map();for(const r of rows)providers.set(r.provider_name,(providers.get(r.provider_name)||0)+1);const newest=scans.filter(s=>s.collected_at&&Number.isFinite(Date.parse(s.collected_at))).sort((a,b)=>Date.parse(b.collected_at)-Date.parse(a.collected_at))[0];const scanCount=scans.filter(s=>s.scan_status==="complete"||s.scan_status==="partial").length,partial=scans.filter(s=>s.scan_status==="partial").length,open=rows.filter(r=>r.review_status==="open").length;const providerRows=[...providers].sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0])).map(([name,count])=>`<tr><td>${reportCell(name)}</td><td>${count.toLocaleString()}</td></tr>`).join("");const findingRows=rows.map(r=>{const detail=[r.browser,r.matched_domain,r.display_name,r.version].filter(Boolean).join(" · ");return `<tr><td>${reportCell(r.provider_name)} · ${reportCell(r.product)}</td><td>${reportCell(labelCategory(r.category))}</td><td>${reportCell(r.confidence)}</td><td>${Number(r.evidence_level||0)}</td><td>${reportCell(r.review_status)}</td><td>${reportCell(detail||"—")}</td></tr>`}).join("");const filters=[$("provider").selectedOptions[0]?.textContent,$("category").value?labelCategory($("category").value):"",$("confidence").value,$("review").value,$("hideReviewed").checked?"Acknowledged/justified hidden":"",$("search").value.trim()?"Search applied":""].filter(Boolean);const timestamp=newest?`${new Intl.DateTimeFormat(undefined,{dateStyle:"medium",timeStyle:"short",timeZone:"UTC"}).format(new Date(newest.collected_at))} UTC`:"No scan timestamp available";const qualityNotice=incompleteClientIds.has(clientId)?'<p class="quality"><strong>Source export incomplete:</strong> a truncated scanner result for this client was excluded. Re-export or rerun that scan before treating this inventory as complete.</p>':"";const report=`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Shadow AI inventory — ${reportCell(client.client_label)}</title><style>*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:#183047;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1100px;margin:auto;padding:38px 28px}.brand{font-size:12px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:#226b88}.head{display:flex;justify-content:space-between;gap:16px;align-items:start;border-bottom:1px solid #d9e2eb;padding-bottom:18px}.head h1{font-size:30px;line-height:1.15;margin:8px 0}.muted{color:#60738a}.scope{padding:12px 15px;background:#e7f2f5;border-left:4px solid #287c91;border-radius:0 8px 8px 0;margin:20px 0}.quality{padding:12px 15px;background:#fff2dc;border-left:4px solid #c68719;border-radius:0 8px 8px 0;margin:14px 0}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}.card,section{background:#fff;border:1px solid #dce4ec;border-radius:12px;padding:16px}.card label{font-size:11px;text-transform:uppercase;color:#60738a;font-weight:700;letter-spacing:.06em}.card strong{display:block;font-size:24px;margin-top:5px}.cols{display:grid;grid-template-columns:1fr 1.5fr;gap:12px}h2{font-size:16px;margin:0 0 10px}table{width:100%;border-collapse:collapse}th,td{text-align:left;vertical-align:top;padding:9px;border-bottom:1px solid #e8edf2;overflow-wrap:anywhere}th{font-size:11px;text-transform:uppercase;color:#60738a;background:#f6f8fa}td{font-size:12px}.actions{display:flex;justify-content:flex-end;margin:0 0 10px}.actions button{border:0;border-radius:7px;padding:9px 13px;background:#245fbd;color:#fff;font-weight:700;cursor:pointer}.foot{font-size:11px;color:#60738a;margin-top:20px}@media(max-width:700px){main{padding:20px 12px}.cards{grid-template-columns:repeat(2,1fr)}.cols{grid-template-columns:1fr}.head{display:block}}@media print{body{background:#fff}main{max-width:none;padding:10mm}.actions{display:none}.card,section{box-shadow:none;break-inside:avoid}tr{break-inside:avoid}table{font-size:9pt}}</style></head><body><main><div class="actions"><button onclick="window.print()" type="button">Print / Save as PDF</button></div><header class="head"><div><div class="brand">RampUp · Security Insights</div><h1>Shadow AI inventory</h1><div class="muted">${reportCell(client.client_label)} · Current-state findings</div></div><div class="muted">Generated ${reportCell(new Date().toISOString().replace("T"," ").slice(0,19))} UTC</div></header>${qualityNotice}<div class="scope"><strong>Scope note:</strong> This report reflects the latest archived scan records only, not a verified count of the client’s full device fleet. Missing signals do not prove absence of AI use. Findings are observations for review, not proof of account use or data exposure.${filters.length?`<br><strong>Active filters:</strong> ${reportCell(filters.join(" · "))}`:""}</div><div class="cards"><div class="card"><label>Endpoints with reported scans</label><strong>${scanCount.toLocaleString()}</strong></div><div class="card"><label>Current finding observations</label><strong>${rows.length.toLocaleString()}</strong></div><div class="card"><label>Open review observations</label><strong>${open.toLocaleString()}</strong></div><div class="card"><label>Newest scan (UTC)</label><strong style="font-size:14px">${reportCell(timestamp)}</strong></div></div><div class="cols"><section><h2>Findings by provider</h2><table><thead><tr><th>Provider</th><th>Observations</th></tr></thead><tbody>${providerRows||"<tr><td colspan=\"2\">No matching findings</td></tr>"}</tbody></table><p class="muted">${partial.toLocaleString()} partial scan records in this client scope.</p></section><section><h2>Finding details</h2><table><thead><tr><th>Provider / product</th><th>Type</th><th>Confidence</th><th>Evidence</th><th>Review</th><th>Metadata</th></tr></thead><tbody>${findingRows||"<tr><td colspan=\"6\">No matching findings</td></tr>"}</tbody></table></section></div><p class="foot">Source: validated Shadow AI collector observations, reduced to each endpoint's latest scan. Counts are finding observations, not unique users or devices. This report is self-contained, makes no network requests, and excludes endpoint/local-user identities and reviewer notes. Treat low-confidence browser-history matches as domain-presence signals only.</p></main></body></html>`;const blob=new Blob([report],{type:"text/html;charset=utf-8"}),url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download=`shadow-ai-${clientId}-current-report.html`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
for(const id of ["client","provider","category","confidence","review","hideReviewed","sortDirection"])$(id).addEventListener("change",()=>{state.page=0;render()});$("search").addEventListener("input",()=>{state.page=0;render()});$("prevPage").addEventListener("click",()=>{if(state.page>0){state.page--;render()}});$("nextPage").addEventListener("click",()=>{state.page++;render()});$("export").addEventListener("click",exportClient);$("reset").addEventListener("click",()=>{for(const id of ["client","provider","category","confidence","review"])$(id).value="";$("hideReviewed").checked=false;$("search").value="";$("sortDirection").value="desc";state.sort="observed_at";state.page=0;render()});for(const b of document.querySelectorAll("th button[data-sort]"))b.addEventListener("click",()=>{if(state.sort===b.dataset.sort)$("sortDirection").value=$("sortDirection").value==="asc"?"desc":"asc";else{state.sort=b.dataset.sort;$("sortDirection").value="asc"}state.page=0;render()});for(const b of document.querySelectorAll("th button[data-client-sort]"))b.addEventListener("click",()=>{if(clientSort.key===b.dataset.clientSort)clientSort.direction=clientSort.direction==="asc"?"desc":"asc";else{clientSort.key=b.dataset.clientSort;clientSort.direction=clientSort.key==="client_label"?"asc":"desc"}render()});
$("lede").textContent=`${data.clients.length.toLocaleString()} client archives · ${data.findings.length.toLocaleString()} current finding observations · ${data.period}`;$("footer").textContent="Source: validated Shadow AI collector observations, reduced to each endpoint's latest scan and mapped through the private client manifest. Finding counts reflect current scan observations, not unique users or devices. This self-contained page sends no telemetry and embeds the included records; restrict file access and regenerate after new scans.";render();
</script></body></html>'''


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="private client-to-archive manifest outside this repository")
    parser.add_argument("--output", required=True, type=Path, help="private HTML file outside this repository; parent mode 0700 or stricter")
    parser.add_argument("--period", type=build_dashboard_feed.parse_period, help="optional collection month filter, YYYY-MM")
    parser.add_argument("--import-note", help="visible source-quality warning for incomplete exports")
    parser.add_argument("--overwrite", action="store_true", help="replace an existing private dashboard")
    args = parser.parse_args(argv)
    try:
        payload = build_payload(args.manifest, args.period, args.import_note)
        path = write_dashboard(args.output, make_html(payload), args.overwrite)
    except (build_dashboard_feed.FeedError, build_report.ReportError, OSError, ValueError) as exc:
        print(f"Could not build internal dashboard: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote private technician dashboard: {path}")
    print(f"Embedded {len(payload['clients'])} client archives, {len(payload['findings'])} finding observations, and {len(payload['scans'])} scan-status rows.")
    print("Keep this self-contained file in an approved, access-controlled location; it includes the included client telemetry.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
