#!/usr/bin/env python3
"""Build a self-contained, interactive Shadow AI HTML report from observations.

The report is client-scoped input: invoke once per client against that client's
private observation archive. Keep observations, reports, and review decisions
out of this public repository.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import validate_observation


ROOT = Path(__file__).resolve().parents[1]
PROVIDER_CATALOG = ROOT / "catalog" / "providers.csv"
REVIEW_STATUSES = {"acknowledged", "justified"}


class ReportError(ValueError):
    """Raised when report inputs are invalid or unsafe to render."""


def parse_month(value: str) -> str:
    try:
        datetime.strptime(value, "%Y-%m")
    except ValueError as exc:
        raise argparse.ArgumentTypeError("period must use YYYY-MM format") from exc
    return value


def collect_paths(values: list[str]) -> list[Path]:
    paths: list[Path] = []
    for raw in values:
        path = Path(raw).expanduser().resolve()
        if path.is_dir():
            paths.extend(sorted(path.glob("*.json")))
        elif path.is_file() and path.suffix.lower() == ".json":
            paths.append(path)
        else:
            raise ReportError(f"not a JSON observation file or directory: {path}")
    unique = list(dict.fromkeys(paths))
    if not unique:
        raise ReportError("no .json observation files found (directories are read non-recursively)")
    return unique


def load_observations(paths: list[Path], period: str | None) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for path in paths:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            validate_observation.validate_document(document)
        except (OSError, json.JSONDecodeError, validate_observation.ObservationError) as exc:
            raise ReportError(f"invalid observation {path.name}: {exc}") from exc
        if period and not str(document["collected_at"]).startswith(period):
            continue
        if document["observation_id"] in seen_ids:
            continue
        seen_ids.add(document["observation_id"])
        observations.append(document)
    observations.sort(key=lambda item: (item["collected_at"], item["device"]["hostname"]))
    if not observations:
        suffix = f" for {period}" if period else ""
        raise ReportError(f"no valid observations found{suffix}")
    return observations


def load_provider_names(path: Path = PROVIDER_CATALOG) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    providers: dict[str, dict[str, Any]] = {}
    indicator_products: dict[str, str] = {}
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                provider_id = row["provider_id"]
                record = providers.setdefault(provider_id, {"name": row["provider_name"], "products": set()})
                if row["product_name"]:
                    record["products"].add(row["product_name"])
                    indicator_products[row["indicator_id"]] = row["product_name"]
    except (OSError, KeyError, csv.Error) as exc:
        raise ReportError(f"could not load provider catalog: {exc}") from exc
    normalized = {key: {"name": value["name"], "products": sorted(value["products"])} for key, value in providers.items()}
    return normalized, indicator_products


def stable_finding_key(document: dict[str, Any], finding: dict[str, Any]) -> str:
    """Return a stable, private review key while ignoring volatile versions/times."""
    attributes = finding["attributes"]
    identity_attributes = {
        key: value
        for key, value in attributes.items()
        if key not in {"version", "observed_at", "last_seen"}
    }
    identity = {
        "hostname": document["device"]["hostname"].casefold(),
        "provider_id": finding["provider_id"],
        "category": finding["category"],
        "indicator_id": finding["indicator_id"],
        "subject_user": finding["subject_user"],
        "attributes": identity_attributes,
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_reviews(path: Path | None) -> dict[str, dict[str, str]]:
    if path is None:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportError(f"could not read review decisions: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != "1.0" or not isinstance(data.get("decisions"), list):
        raise ReportError("review file must have schema_version 1.0 and a decisions array")
    decisions: dict[str, dict[str, str]] = {}
    for index, row in enumerate(data["decisions"]):
        if not isinstance(row, dict):
            raise ReportError(f"review decision {index} must be an object")
        key = row.get("finding_key")
        status = row.get("status")
        if not isinstance(key, str) or len(key) != 64 or any(char not in "0123456789abcdef" for char in key):
            raise ReportError(f"review decision {index} has an invalid finding_key")
        if status not in REVIEW_STATUSES:
            raise ReportError(f"review decision {index} has an unsupported status")
        reviewer = row.get("reviewer")
        reason = row.get("reason")
        reviewed_at = row.get("reviewed_at")
        if any(not isinstance(value, str) or not value.strip() for value in (reviewer, reason, reviewed_at)):
            raise ReportError(f"review decision {index} needs reviewer, reason, and reviewed_at")
        decisions[key] = {
            "status": status,
            "reviewer": reviewer.strip()[:120],
            "reason": reason.strip()[:500],
            "reviewed_at": reviewed_at.strip()[:40],
        }
    return decisions


def build_rows(
    observations: list[dict[str, Any]],
    providers: dict[str, dict[str, Any]],
    indicator_products: dict[str, str],
    decisions: dict[str, dict[str, str]],
    include_local_users: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for document in observations:
        for finding in document["findings"]:
            attributes = finding["attributes"]
            provider = providers.get(finding["provider_id"], {"name": finding["provider_id"], "products": []})
            product_hint = attributes.get("extension_name") or attributes.get("display_name")
            if not product_hint:
                product_hint = indicator_products.get(finding["indicator_id"])
            if not product_hint:
                product_hint = provider["products"][0] if provider["products"] else finding["capability"].replace("_", " ").title()
            details = []
            for key in ("browser", "matched_domain", "extension_id", "classification_basis", "display_name", "version", "process_name", "location"):
                value = attributes.get(key)
                if isinstance(value, (str, int, float)) and str(value).strip():
                    details.append({"label": key.replace("_", " ").title(), "value": str(value)[:500]})
            key = stable_finding_key(document, finding)
            review = decisions.get(key)
            row = {
                "finding_key": key,
                "observed_at": finding["observed_at"],
                "collected_at": document["collected_at"],
                "hostname": document["device"]["hostname"],
                "os_family": document["device"]["os_family"],
                "provider_id": finding["provider_id"],
                "provider_name": provider["name"],
                "product_hint": product_hint,
                "category": finding["category"],
                "confidence": finding["confidence"],
                "evidence_level": finding["evidence_level"],
                "details": details,
                "review": review,
            }
            if include_local_users and finding["subject_user"]:
                row["local_user"] = finding["subject_user"]
            rows.append(row)
    rows.sort(key=lambda row: (row["observed_at"], row["hostname"], row["provider_id"]), reverse=True)
    return rows


def safe_json_for_html(value: Any) -> str:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def ensure_private_output(path: Path) -> None:
    try:
        path.relative_to(ROOT)
    except ValueError:
        return
    raise ReportError("report output must be outside the public repository")


def make_html(
    observations: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    client_label: str,
    period: str | None,
    decisions: dict[str, dict[str, str]],
    include_local_users: bool,
) -> str:
    hosts = sorted({item["device"]["hostname"] for item in observations})
    partial = sum(bool(item["collector"]["partial"]) for item in observations)
    period_label = period or (
        observations[0]["collected_at"][:7]
        if observations[0]["collected_at"][:7] == observations[-1]["collected_at"][:7]
        else f"{observations[0]['collected_at'][:10]} – {observations[-1]['collected_at'][:10]}"
    )
    relevant_review_keys = {row["finding_key"] for row in rows if row["review"]}
    payload = {
        "client_label": client_label,
        "period_label": period_label,
        "observations": len(observations),
        "devices": len(hosts),
        "partial_scans": partial,
        "scans": [
            {
                "collected_at": item["collected_at"],
                "hostname": item["device"]["hostname"],
                "os_family": item["device"]["os_family"],
                "collector_version": item["collector"]["version"],
                "partial": item["collector"]["partial"],
                "errors": item["collector"]["errors"],
                "scope": item["scope"],
            }
            for item in observations
        ],
        "rows": rows,
        # Never copy orphaned decisions into this report. Besides avoiding stale
        # rows, this protects against accidentally supplying another tenant's
        # review sidecar with reviewer names and reasons.
        "reviews": {key: value for key, value in decisions.items() if key in relevant_review_keys},
        "include_local_users": include_local_users,
    }
    escaped_label = html.escape(client_label, quote=True)
    escaped_period = html.escape(period_label, quote=True)
    return REPORT_HTML.replace("{{CLIENT_LABEL}}", escaped_label).replace("{{PERIOD_LABEL}}", escaped_period).replace(
        "{{REPORT_DATA}}", safe_json_for_html(payload)
    )


REPORT_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; base-uri 'none'; form-action 'none'">
<title>Shadow AI inventory — {{CLIENT_LABEL}}</title>
<style>
:root{color-scheme:light;--ink:#15273a;--muted:#617285;--line:#d9e1e8;--paper:#f4f7fa;--card:#fff;--navy:#102a43;--blue:#2878a8;--teal:#1b8a83;--gold:#d49a37;--red:#ae4b4b;--green:#2d8063;--shadow:0 12px 36px rgba(20,42,62,.08)}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1440px;margin:auto;padding:34px clamp(16px,3vw,44px) 52px}.topline{display:flex;justify-content:space-between;gap:20px;align-items:center;border-bottom:1px solid var(--line);padding:0 0 22px}.brand{display:flex;gap:12px;align-items:center;font-weight:700;letter-spacing:.02em;color:var(--navy)}.mark{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,var(--teal),var(--blue));display:inline-flex;align-items:center;justify-content:center;color:#fff;font-weight:800}.period{color:var(--muted);font-size:13px}.title{margin:28px 0 8px;font-size:clamp(29px,4vw,44px);letter-spacing:-.035em;line-height:1.08;color:var(--navy)}.lede{margin:0;color:var(--muted);max-width:850px}.summary{margin-top:24px;border-left:4px solid var(--teal);padding:16px 20px;background:#eaf5f3;border-radius:0 12px 12px 0;color:#214a49}.summary strong{color:#153d3b}.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:22px 0}.card,.panel{background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow)}.kpi{padding:19px 20px}.kpi-label{display:block;color:var(--muted);font-size:12px;font-weight:650;text-transform:uppercase;letter-spacing:.07em}.kpi-value{font-size:34px;font-weight:750;letter-spacing:-.04em;margin-top:6px;color:var(--navy)}.kpi-note{color:var(--muted);font-size:12px;margin-top:2px}.controls{display:flex;align-items:end;flex-wrap:wrap;gap:12px;padding:18px 20px;margin:18px 0 14px}.control{display:grid;gap:5px;min-width:175px}.control label,.checkbox{font-size:12px;color:var(--muted);font-weight:650}.control select,.control input{height:40px;border:1px solid #c8d3de;border-radius:9px;padding:0 10px;color:var(--ink);background:white;font:inherit}.checkbox{display:flex;align-items:center;gap:8px;height:40px}.checkbox input{accent-color:var(--teal);width:17px;height:17px}.button{border:0;border-radius:9px;background:var(--navy);color:#fff;font-weight:650;padding:11px 15px;cursor:pointer}.button:hover{background:#1c4868}.button.secondary{background:#e7eef4;color:#18374f}.button.small{padding:6px 9px;font-size:12px}.dashboard-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.panel{padding:20px;min-width:0}.panel h2{font-size:17px;margin:0;color:var(--navy)}.panel-intro{color:var(--muted);font-size:12px;margin:3px 0 16px}.bar-list{display:grid;gap:12px}.bar-row{display:grid;grid-template-columns:minmax(100px,165px) 1fr 42px;align-items:center;gap:10px;font-size:13px}.bar-label{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.bar-track{height:10px;background:#edf1f5;border-radius:99px;overflow:hidden}.bar-fill{height:100%;background:linear-gradient(90deg,var(--teal),#47a8a1);border-radius:99px;min-width:2px}.bar-value{text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}.trend{height:154px;display:flex;align-items:end;gap:8px;padding:10px 2px 0;border-bottom:1px solid var(--line)}.trend-col{flex:1;min-width:18px;height:100%;display:flex;flex-direction:column;justify-content:end;align-items:center;gap:7px}.trend-count{font-size:11px;color:var(--muted)}.trend-bar{width:min(42px,100%);min-height:2px;background:linear-gradient(180deg,#32969b,#2878a8);border-radius:7px 7px 2px 2px}.trend-date{font-size:10px;color:var(--muted);white-space:nowrap;transform:translateY(19px)}.table-panel{margin-top:16px;padding:0;overflow:hidden}.table-head{padding:20px 20px 12px;display:flex;justify-content:space-between;align-items:center;gap:12px}.table-note{padding:0 20px 12px;color:var(--muted);font-size:12px}.table-wrap{overflow:auto;max-height:660px;border-top:1px solid var(--line)}table{width:100%;border-collapse:collapse;min-width:940px}th,td{text-align:left;padding:12px 14px;border-bottom:1px solid #e9eef2;vertical-align:top}th{position:sticky;top:0;background:#f7f9fb;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em;z-index:1}td{font-size:13px}.product{font-weight:700;color:var(--navy)}.sub{display:block;color:var(--muted);font-size:11px;margin-top:3px}.badge{display:inline-flex;border-radius:99px;padding:3px 8px;font-size:11px;font-weight:700;background:#edf1f5;color:#415568}.badge.high{background:#e6f3ed;color:#27684f}.badge.medium{background:#fff4dd;color:#805b1c}.badge.low{background:#f8eaea;color:#934444}.badge.acknowledged,.badge.justified{background:#e9eef8;color:#455b82}.details{max-width:310px;overflow-wrap:anywhere}.empty{padding:28px;text-align:center;color:var(--muted)}.foot{margin-top:20px;color:var(--muted);font-size:11px}.foot summary{cursor:pointer;font-weight:700;color:#44576b}.foot p{max-width:1000px}.callout{border-radius:10px;padding:11px 14px;background:#fff5e2;color:#71531b;font-size:12px;margin:14px 0}.actions{display:flex;gap:6px;flex-wrap:wrap}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media(max-width:850px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.dashboard-grid{grid-template-columns:1fr}.topline{align-items:flex-start;flex-direction:column}.controls{align-items:stretch}.control{flex:1 1 210px}}
@media(max-width:480px){main{padding:20px 13px 36px}.kpis{gap:8px}.kpi{padding:14px}.kpi-value{font-size:28px}.panel{padding:16px}.bar-row{grid-template-columns:minmax(88px,120px) 1fr 30px;gap:7px}}
@media print{body{background:#fff}main{max-width:none;padding:12mm}.card,.panel{box-shadow:none;break-inside:avoid}.controls,.actions,.foot details{display:none!important}.table-wrap{max-height:none;overflow:visible}table{min-width:0;font-size:9pt}th{position:static}.table-panel{overflow:visible}.dashboard-grid{grid-template-columns:1fr 1fr}.trend{height:120px}}
</style>
</head>
<body>
<main>
  <header class="topline"><div class="brand"><span class="mark" aria-hidden="true">R</span><span>RampUp · Security Insights</span></div><div class="period"><span id="clientLabel">{{CLIENT_LABEL}}</span> &nbsp;·&nbsp; Reporting period <strong>{{PERIOD_LABEL}}</strong></div></header>
  <h1 class="title">AI tools and browser signals, at a glance</h1>
  <p class="lede">A reviewable inventory of AI-related software, browser extensions, and matched website-domain indicators observed on the selected client’s endpoints.</p>
  <section class="summary" aria-label="Executive summary"><strong id="summaryText">Loading report summary…</strong></section>
  <section class="kpis" aria-label="Key measures">
    <article class="card kpi"><span class="kpi-label">Endpoints scanned</span><div class="kpi-value" id="kpiDevices">—</div><div class="kpi-note" id="kpiScans">—</div></article>
    <article class="card kpi"><span class="kpi-label">Visible observations</span><div class="kpi-value" id="kpiFindings">—</div><div class="kpi-note">Matches in the selected filters</div></article>
    <article class="card kpi"><span class="kpi-label">AI providers observed</span><div class="kpi-value" id="kpiProviders">—</div><div class="kpi-note">Distinct providers in view</div></article>
    <article class="card kpi"><span class="kpi-label">Reviewed findings</span><div class="kpi-value" id="kpiReviewed">—</div><div class="kpi-note">May be hidden; source observations remain unchanged</div></article>
  </section>
  <div class="callout" id="coverageNote" role="status"></div>
<section class="controls card" aria-label="Report filters">
    <div class="control"><label for="providerFilter">AI product / provider</label><select id="providerFilter"><option value="">All detected products</option></select></div>
    <div class="control"><label for="categoryFilter">Evidence type</label><select id="categoryFilter"><option value="">All evidence types</option><option value="software">Installed software</option><option value="browser_extension">Browser extensions</option><option value="browser_history">Website-domain indicators</option><option value="process">Running processes</option><option value="model_directory">Model directories</option><option value="config_file">Configuration presence</option></select></div>
    <div class="control"><label for="confidenceFilter">Confidence</label><select id="confidenceFilter"><option value="">All confidence levels</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
    <div class="control" style="flex:1 1 220px"><label for="searchFilter">Search findings</label><input id="searchFilter" type="search" placeholder="Product, device, domain…" autocomplete="off"></div>
    <label class="checkbox"><input id="hideReviewed" type="checkbox" checked> Hide acknowledged / justified</label>
    <button class="button secondary" id="exportReviews" type="button">Download review decisions</button>
  </section>
  <section class="dashboard-grid" aria-label="Finding summaries">
    <article class="panel"><h2>What appeared in the selected view</h2><p class="panel-intro">Observed finding occurrences, grouped by provider.</p><div class="bar-list" id="providerChart"></div></article>
    <article class="panel"><h2>Evidence types</h2><p class="panel-intro">Each signal is an observation, not proof of account use or policy violation.</p><div class="bar-list" id="categoryChart"></div></article>
    <article class="panel" style="grid-column:1/-1"><h2>Collection activity</h2><p class="panel-intro">Finding occurrences by scan date. Repeated observations across scans are expected.</p><div class="trend" id="trendChart"></div></article>
  </section>
  <details class="panel" style="margin-top:16px"><summary style="cursor:pointer;font-weight:700;color:var(--navy)">Collection coverage by endpoint and run</summary><p class="panel-intro">Expand to inspect collector version, collection areas, and any reported gaps.</p><div class="table-wrap"><table style="min-width:700px"><thead><tr><th>Collected</th><th>Endpoint</th><th>OS</th><th>Collector</th><th>Coverage</th><th>Scope / gaps</th></tr></thead><tbody id="scansBody"></tbody></table></div></details>
  <section class="panel table-panel" aria-label="Detailed findings">
    <div class="table-head"><div><h2>Findings to review</h2><div class="panel-intro" style="margin-bottom:0">Use filters to focus the review; mark justified activity without deleting its observation.</div></div><div id="resultCount" class="period"></div></div>
    <div class="table-note" id="reviewNote"></div>
    <div class="table-wrap"><table><thead><tr><th>Observed</th><th>Product / provider</th><th>Evidence</th><th>Endpoint</th><th>Confidence</th><th>Review state</th><th class="actions-col">Review</th></tr></thead><tbody id="findingsBody"></tbody></table><div class="empty" id="emptyState" hidden>No findings match these filters.</div><div class="table-note" id="limitNote" hidden></div></div>
  </section>
  <footer class="foot"><details><summary>Scope, interpretation, and handling</summary><p>Collector observations indicate that a cataloged artifact, extension, or domain signal was present. They do not establish that an individual logged in, submitted data, or violated policy. Browser-history indicators are presence-only; the Windows collector uses a bounded local string match and may encounter stale database strings. Low-confidence matches warrant review. Partial scans represent incomplete coverage, not negative results.</p><p>Review decisions are client-specific and are applied only to this report. The report is self-contained and includes endpoint-level metadata; store and share it only in an approved, access-controlled client location. Local-user identities are excluded unless the report was deliberately built with the opt-in flag. No external resources or network requests are used by this page.</p></details><p id="builtAt"></p></footer>
</main>
<script id="report-data" type="application/json">{{REPORT_DATA}}</script>
<script>
"use strict";
const data=JSON.parse(document.getElementById("report-data").textContent);
const state={reviews:{...data.reviews}};
const $=id=>document.getElementById(id);
const esc=value=>String(value??"");
const fmtDate=value=>{const d=new Date(value);return Number.isNaN(d.valueOf())?esc(value):new Intl.DateTimeFormat(undefined,{dateStyle:"medium",timeStyle:"short"}).format(d)};
const allRows=data.rows;
const products=new Map();
for(const row of allRows){products.set(`${row.provider_id}|${row.product_hint}`,{id:row.provider_id,product:row.product_hint,provider:row.provider_name})}
for(const [key,item] of [...products.entries()].sort((a,b)=>a[1].product.localeCompare(b[1].product)||a[1].provider.localeCompare(b[1].provider))){const option=document.createElement("option");option.value=key;option.textContent=`${item.product} (${item.provider})`;$("providerFilter").append(option)}
function currentRows(){const selected=$("providerFilter").value,parts=selected?selected.split("|",2):[],provider=parts[0],product=parts[1],category=$("categoryFilter").value,confidence=$("confidenceFilter").value,query=$("searchFilter").value.trim().toLocaleLowerCase(),hide=$("hideReviewed").checked;return allRows.filter(row=>{const review=state.reviews[row.finding_key];if(provider&&(row.provider_id!==provider||row.product_hint!==product))return false;if(category&&row.category!==category)return false;if(confidence&&row.confidence!==confidence)return false;if(hide&&review)return false;if(query){const hay=[row.provider_name,row.product_hint,row.hostname,row.category,...row.details.map(x=>x.value),row.local_user||""].join(" ").toLocaleLowerCase();if(!hay.includes(query))return false}return true})}
function makeBarList(targetId,counts){const root=$(targetId);root.replaceChildren();const entries=[...counts.entries()].sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0])).slice(0,8),max=Math.max(1,...entries.map(item=>item[1]));if(!entries.length){const empty=document.createElement("div");empty.className="empty";empty.textContent="No findings in this view.";root.append(empty);return}for(const [label,value] of entries){const row=document.createElement("div");row.className="bar-row";const name=document.createElement("span");name.className="bar-label";name.textContent=label;const track=document.createElement("div");track.className="bar-track";const fill=document.createElement("div");fill.className="bar-fill";fill.style.width=`${Math.max(2,value/max*100)}%`;track.append(fill);const count=document.createElement("span");count.className="bar-value";count.textContent=String(value);row.append(name,track,count);root.append(row)}}
function renderTrend(rows){const target=$("trendChart");target.replaceChildren();const counts=new Map();for(const row of rows){const day=row.collected_at.slice(0,10);counts.set(day,(counts.get(day)||0)+1)}const entries=[...counts.entries()].sort((a,b)=>a[0].localeCompare(b[0])).slice(-12),max=Math.max(1,...entries.map(item=>item[1]));if(!entries.length){target.textContent="No observations in this view.";return}for(const [day,count] of entries){const column=document.createElement("div");column.className="trend-col";const amount=document.createElement("span");amount.className="trend-count";amount.textContent=String(count);const bar=document.createElement("div");bar.className="trend-bar";bar.style.height=`${Math.max(2,count/max*100)}%`;bar.title=`${day}: ${count} finding occurrences`;const date=document.createElement("span");date.className="trend-date";date.textContent=day.slice(5);column.append(amount,bar,date);target.append(column)}}
function renderScans(){const body=$("scansBody");body.replaceChildren();for(const scan of data.scans){const tr=document.createElement("tr");for(const value of [fmtDate(scan.collected_at),scan.hostname,scan.os_family,scan.collector_version,scan.partial?"Partial":"Complete",[...scan.scope,...scan.errors].join(" · ")]){const td=document.createElement("td");td.textContent=value;tr.append(td)}body.append(tr)}}
function render(){const rows=currentRows(),reviewed=allRows.filter(row=>state.reviews[row.finding_key]).length,providers=new Set(rows.map(row=>row.provider_id));$("kpiDevices").textContent=data.devices.toLocaleString();$("kpiScans").textContent=`${data.observations.toLocaleString()} scans · ${data.partial_scans.toLocaleString()} partial`;$("kpiFindings").textContent=rows.length.toLocaleString();$("kpiProviders").textContent=providers.size.toLocaleString();$("kpiReviewed").textContent=reviewed.toLocaleString();$("resultCount").textContent=`${rows.length.toLocaleString()} shown of ${allRows.length.toLocaleString()}`;$("summaryText").textContent=allRows.length?`${data.client_label}: ${data.devices.toLocaleString()} endpoints were observed in ${data.period_label}; ${allRows.length.toLocaleString()} finding occurrences are available for review, including ${reviewed.toLocaleString()} already acknowledged or justified.`:`${data.client_label}: scans completed for ${data.period_label}, with no findings recorded.`;$("reviewNote").textContent=reviewed?`${reviewed.toLocaleString()} finding occurrences have a saved review decision. Uncheck “Hide acknowledged / justified” to inspect them; decisions can be downloaded for the next report.`:"No saved acknowledgements or justifications are attached to this report.";$("coverageNote").textContent=data.partial_scans?`${data.partial_scans} of ${data.observations} scans reported partial collection. Treat endpoints without a signal as unknown where the relevant collection area was incomplete.`:`All ${data.observations} included scans reported complete collection. This is collection health, not proof that every possible AI signal is detected.`;const providerCounts=new Map();for(const row of rows)providerCounts.set(row.provider_name,(providerCounts.get(row.provider_name)||0)+1);makeBarList("providerChart",providerCounts);const categoryCounts=new Map();for(const row of rows){const label=row.category.replaceAll("_"," ");categoryCounts.set(label,(categoryCounts.get(label)||0)+1)}makeBarList("categoryChart",categoryCounts);renderTrend(rows);renderScans();const body=$("findingsBody");body.replaceChildren();$("emptyState").hidden=rows.length>0;const shown=rows.slice(0,2000);$("limitNote").hidden=rows.length<=2000;$("limitNote").textContent=rows.length>2000?"Showing the newest 2,000 matching rows. Refine filters for the complete view.":"";for(const row of shown){const tr=document.createElement("tr");const observed=document.createElement("td");observed.textContent=fmtDate(row.observed_at);const product=document.createElement("td");const productName=document.createElement("span");productName.className="product";productName.textContent=row.product_hint;const provider=document.createElement("span");provider.className="sub";provider.textContent=row.provider_name;product.append(productName,provider);const evidence=document.createElement("td");const category=document.createElement("span");category.textContent=row.category.replaceAll("_"," ");evidence.append(category);for(const detail of row.details){const line=document.createElement("span");line.className="sub";line.textContent=`${detail.label}: ${detail.value}`;evidence.append(line)}if(row.local_user){const user=document.createElement("span");user.className="sub";user.textContent=`Local user: ${row.local_user}`;evidence.append(user)}const endpoint=document.createElement("td");endpoint.textContent=row.hostname;const conf=document.createElement("td");const confidence=document.createElement("span");confidence.className=`badge ${row.confidence}`;confidence.textContent=row.confidence;conf.append(confidence);const reviewCell=document.createElement("td"),review=state.reviews[row.finding_key];if(review){const badge=document.createElement("span");badge.className=`badge ${review.status}`;badge.textContent=review.status;reviewCell.append(badge);const reason=document.createElement("span");reason.className="sub";reason.textContent=review.reason;reviewCell.append(reason)}else{reviewCell.textContent="Needs review"}const actions=document.createElement("td"),wrap=document.createElement("div");wrap.className="actions";for(const status of ["acknowledged","justified"]){const button=document.createElement("button");button.type="button";button.className="button small secondary";button.textContent=review&&review.status===status?`Update ${status}`:`Mark ${status}`;button.addEventListener("click",()=>markReview(row,status));wrap.append(button)}if(review){const clear=document.createElement("button");clear.type="button";clear.className="button small secondary";clear.textContent="Clear";clear.addEventListener("click",()=>{delete state.reviews[row.finding_key];render()});wrap.append(clear)}actions.append(wrap);tr.append(observed,product,evidence,endpoint,conf,reviewCell,actions);body.append(tr)}}
function markReview(row,status){const reviewer=window.prompt("Reviewer name or role (stored in the private review file):");if(!reviewer||!reviewer.trim())return;const reason=window.prompt("Why is this finding acknowledged or justified?");if(!reason||!reason.trim())return;state.reviews[row.finding_key]={status,reviewer:reviewer.trim(),reason:reason.trim(),reviewed_at:new Date().toISOString()};render()}
function exportReviews(){const decisions=Object.entries(state.reviews).map(([finding_key,review])=>({finding_key,...review})).sort((a,b)=>a.finding_key.localeCompare(b.finding_key));const blob=new Blob([JSON.stringify({schema_version:"1.0",decisions},null,2)+"\n"],{type:"application/json"});const url=URL.createObjectURL(blob),link=document.createElement("a");link.href=url;link.download="shadow-ai-review-decisions.json";link.click();URL.revokeObjectURL(url)}
for(const id of ["providerFilter","categoryFilter","confidenceFilter","hideReviewed"]){$(id).addEventListener("change",render)}$("searchFilter").addEventListener("input",render);$("exportReviews").addEventListener("click",exportReviews);$("builtAt").textContent=`Prepared ${new Intl.DateTimeFormat(undefined,{dateStyle:"medium"}).format(new Date())} · ${data.include_local_users?"Local-user identifiers included by explicit opt-in":"Local-user identities omitted"}`;render();
</script>
</body></html>
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", nargs="+", required=True, help="JSON files and/or a private archive directory (non-recursive)")
    parser.add_argument("--output", required=True, help="destination HTML path; keep it outside the public repository")
    parser.add_argument("--client-label", required=True, help="display label for this single-client report")
    parser.add_argument("--period", type=parse_month, help="include only observations from YYYY-MM")
    parser.add_argument("--reviews", help="private review-decision JSON exported from a prior report")
    parser.add_argument("--include-local-users", action="store_true", help="include local account names; omitted by default")
    args = parser.parse_args()
    try:
        observations = load_observations(collect_paths(args.observations), args.period)
        decisions = load_reviews(Path(args.reviews).expanduser().resolve() if args.reviews else None)
        providers, indicator_products = load_provider_names()
        rows = build_rows(observations, providers, indicator_products, decisions, args.include_local_users)
        output = Path(args.output).expanduser().resolve()
        ensure_private_output(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            make_html(observations, rows, args.client_label, args.period, decisions, args.include_local_users),
            encoding="utf-8",
        )
    except (ReportError, OSError) as exc:
        print(f"Report not created: {exc}", file=sys.stderr)
        return 1
    print(f"Created client-scoped HTML report: {output}")
    print(f"Included {len(observations)} scans and {len(rows)} finding occurrences; local-user identities {'included' if args.include_local_users else 'omitted'}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
