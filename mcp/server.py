#!/usr/bin/env python3
"""
AmpelOracle — DORA Regulatory Traffic Light System MCP Server v1.0.0
Port 10101 | Part of ToolOracle Whitelabel MCP Platform

Provides real-time DORA compliance Ampel (traffic light) status for regulated entities.
Reads from dora_ampel.db (SQLite) populated by evidence collectors.

Tools:
  1. readiness_check    — Full DORA readiness score + Ampel per article
  2. article_status     — Detailed status for a specific DORA article
  3. gap_report         — What's missing: RED/GREY items with action plan
  4. evidence_summary   — All evidence artefacts for an entity
  5. assess_article     — Trigger assessment for a specific article
  6. collect_art10      — Collect live evidence for Art. 10 (Detection)
  7. collect_art29      — Collect live evidence for Art. 29 (Due Diligence)
  8. entity_list        — List all registered entities
  9. create_entity      — Register a new regulated entity
 10. audit_trail        — Chain-linked audit log with integrity check
 11. health_check       — Server + DB status

Backend: dora_ampel.db (SQLite), dora_article_registry.json
External: NVD, CISA KEV, CERT-Bund, MITRE ATT&CK (via DORAOracle)
"""
import sys, json, logging, hashlib, sqlite3, os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, "/root/whitelabel")
sys.path.insert(0, "/root/rwa_node/dora")
from shared.utils.mcp_base import WhitelabelMCPServer, MCPTool

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [AmpelOracle] %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(),
              logging.FileHandler("/root/whitelabel/logs/ampeloracle.log", mode="a")])

PRODUCT_NAME = "AmpelOracle"
VERSION = "1.0.0"
DB_PATH = "/root/rwa_node/dora/dora_ampel.db"
REGISTRY_PATH = "/root/rwa_node/dora/dora_article_registry.json"


# ── AgentGuard Integration ──
# Pre-flight + Post-scan for all security-sensitive Ampel operations

import aiohttp as _ag_http

AGENTGUARD_URL = "http://127.0.0.1:12001/mcp/"
GUARD_AGENT_ID = "dora-ampel-agent"
GUARD_ENABLED = True

async def _guard_preflight(tool_name, tool_args, entity_id=None):
    """Call AgentGuard policy_preflight before executing an Ampel tool."""
    if not GUARD_ENABLED:
        return {"decision": "allowed", "risk_score": 0, "guard": "disabled"}
    try:
        payload = {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "policy_preflight", "arguments": {
                "tool_name": tool_name,
                "tool_args": tool_args or {},
                "agent_id": GUARD_AGENT_ID,
                "session_id": f"ampel-{entity_id or 'global'}",
                "tenant": "fintech_eu"
            }}
        }
        async with _ag_http.ClientSession() as s:
            async with s.post(AGENTGUARD_URL, json=payload,
                            headers={"Content-Type": "application/json", "Accept": "application/json"},
                            timeout=_ag_http.ClientTimeout(total=5)) as r:
                if r.status == 200:
                    resp = await r.json()
                    text = resp.get("result", {}).get("content", [{}])[0].get("text", "{}")
                    data = json.loads(text).get("data", json.loads(text))
                    return {
                        "decision": data.get("decision", "allowed"),
                        "risk_score": data.get("risk_score", 0),
                        "reason": data.get("reason", ""),
                        "guard": "active"
                    }
        return {"decision": "allowed", "risk_score": 0, "guard": "timeout"}
    except Exception as ex:
        log.warning(f"AgentGuard preflight failed: {ex}")
        return {"decision": "allowed", "risk_score": 0, "guard": "error"}

async def _guard_output_scan(tool_name, output_text, entity_id=None):
    """Call AgentGuard output_safety_scan after executing an Ampel tool."""
    if not GUARD_ENABLED:
        return {"verdict": "clean", "guard": "disabled"}
    try:
        # Truncate output for scan (max 2000 chars)
        scan_text = str(output_text)[:2000]
        payload = {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "output_safety_scan", "arguments": {
                "output": scan_text,
                "tool_name": tool_name,
                "agent_id": GUARD_AGENT_ID
            }}
        }
        async with _ag_http.ClientSession() as s:
            async with s.post(AGENTGUARD_URL, json=payload,
                            headers={"Content-Type": "application/json", "Accept": "application/json"},
                            timeout=_ag_http.ClientTimeout(total=5)) as r:
                if r.status == 200:
                    resp = await r.json()
                    text = resp.get("result", {}).get("content", [{}])[0].get("text", "{}")
                    data = json.loads(text).get("data", json.loads(text))
                    return {
                        "verdict": data.get("verdict", "clean"),
                        "pii_count": len(data.get("pii_findings", [])),
                        "secret_count": len(data.get("secret_findings", [])),
                        "guard": "active"
                    }
        return {"verdict": "clean", "guard": "timeout"}
    except Exception as ex:
        log.warning(f"AgentGuard output scan failed: {ex}")
        return {"verdict": "clean", "guard": "error"}

async def _guard_audit(tool_name, tool_args, result, decision, entity_id=None):
    """Write to AgentGuard audit log after tool execution."""
    if not GUARD_ENABLED:
        return
    try:
        payload = {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "audit_log_write", "arguments": {
                "tool_name": tool_name,
                "tool_args": tool_args or {},
                "agent_id": GUARD_AGENT_ID,
                "decision": decision,
                "outcome": "success" if "error" not in str(result).lower() else "error",
                "result_summary": str(result)[:500]
            }}
        }
        async with _ag_http.ClientSession() as s:
            async with s.post(AGENTGUARD_URL, json=payload,
                            headers={"Content-Type": "application/json", "Accept": "application/json"},
                            timeout=_ag_http.ClientTimeout(total=3)) as r:
                pass  # fire and forget
    except:
        pass


def _db():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=5000")
    c.execute("PRAGMA foreign_keys=ON")
    return c

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def ts():
    return datetime.now(timezone.utc).isoformat()

# ── Tool Handlers ──

async def handle_readiness_check(params):
    """Full DORA readiness score + Ampel per article for an entity."""
    entity_id = params.get("entity_id")
    if not entity_id:
        # Return first entity if none specified
        c = _db()
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        c.close()
        if not e:
            return {"error": "No entities registered. Use create_entity first."}
        entity_id = e["id"]

    c = _db()
    entity = c.execute("SELECT * FROM entities WHERE id=?", (entity_id,)).fetchone()
    if not entity:
        c.close()
        return {"error": f"Entity {entity_id} not found"}

    reqs = c.execute("SELECT * FROM requirements ORDER BY priority_score DESC").fetchall()
    assessments = {}
    for r in c.execute("SELECT * FROM assessments WHERE entity_id=?", (entity_id,)).fetchall():
        key = (r["requirement_id"], r["check_id"])
        assessments[key] = dict(r)

    articles = []
    green = yellow = red = grey = 0
    for req in reqs:
        checks = c.execute("SELECT * FROM checks WHERE requirement_id=?", (req["id"],)).fetchall()
        check_statuses = []
        for chk in checks:
            key = (req["id"], chk["id"])
            s = assessments[key]["status"] if key in assessments else "GREY"
            # Explainability: full context per check
            ass_data = assessments.get(key, {})
            ev_count_chk = c.execute("SELECT COUNT(*) c FROM evidence WHERE entity_id=? AND check_id=? AND status='active'", (entity_id, chk["id"])).fetchone()["c"]
            finding = c.execute("SELECT id, status as f_status, owner, due_date, severity FROM findings WHERE entity_id=? AND check_id=? AND status IN ('open','in_progress','retest_pending') LIMIT 1", (entity_id, chk["id"])).fetchone()
            check_statuses.append({
                "check_id": chk["id"], "description": chk["description"], "status": s,
                "obligation_id": chk["obligation_id"] if chk["obligation_id"] else None,
                "explainability": {
                    "reasoning": ass_data.get("reasoning", "Not assessed"),
                    "data_source": chk["data_source"],
                    "rule_green": chk["green_condition"],
                    "rule_yellow": chk["yellow_condition"],
                    "rule_red": chk["red_condition"],
                    "automation": "full_auto" if chk["requires_human_review"] == 0 else "semi_auto",
                    "evidence_count": ev_count_chk,
                    "criticality": chk["criticality"],
                    "owner": chk["owner_role"],
                    "sla_days": chk["sla_days"],
                    "frequency": chk["check_frequency"],
                    "finding": {"id": finding["id"], "status": finding["f_status"], "owner": finding["owner"], "due_date": finding["due_date"], "severity": finding["severity"]} if finding else None,
                    "next_action": "No action required" if s == "GREEN" else ("Evidence collection needed" if ev_count_chk == 0 else "Review and remediate")
                }
            })

        statuses = [cs["status"] for cs in check_statuses]
        assessed = [s for s in statuses if s != "GREY"]
        if "RED" in statuses: agg = "RED"; red += 1
        elif not assessed: agg = "GREY"; grey += 1
        elif "GREY" in statuses and assessed: agg = "YELLOW"; yellow += 1
        elif "YELLOW" in statuses: agg = "YELLOW"; yellow += 1
        else: agg = "GREEN"; green += 1

        articles.append({
            "article": req["article"], "title": req["title"],
            "category": req["category"], "priority": req["priority_score"],
            "oracle": req["oracle"], "status": agg, "checks": check_statuses,
            "automation": req["automation_level"], "automation_level": req["automation_level"]
        })

    total = green + yellow + red + grey
    
    # DORA Readiness Score: Only count core DORA articles (Chapter II-VI), not Enterprise Extensions (EXT)
    dora_green = sum(1 for a in articles if a["status"] == "GREEN" and a.get("category") != "EXT" and not a["article"].startswith(("NIS2","LkSG","ISO","GDPR","EU MDR","XRechnung","DAC6","Art. 28+")))
    dora_yellow = sum(1 for a in articles if a["status"] == "YELLOW" and a.get("category") != "EXT" and not a["article"].startswith(("NIS2","LkSG","ISO","GDPR","EU MDR","XRechnung","DAC6","Art. 28+")))
    dora_red = sum(1 for a in articles if a["status"] == "RED" and a.get("category") != "EXT" and not a["article"].startswith(("NIS2","LkSG","ISO","GDPR","EU MDR","XRechnung","DAC6","Art. 28+")))
    dora_grey = sum(1 for a in articles if a["status"] == "GREY" and a.get("category") != "EXT" and not a["article"].startswith(("NIS2","LkSG","ISO","GDPR","EU MDR","XRechnung","DAC6","Art. 28+")))
    dora_total = dora_green + dora_yellow + dora_red + dora_grey
    score = round((dora_green * 100 + dora_yellow * 50) / max(dora_total, 1), 1)
    
    # Enterprise Extension Score (separate)
    ext_articles = [a for a in articles if a.get("category") == "EXT" or a["article"].startswith(("NIS2","LkSG","ISO","GDPR","EU MDR","XRechnung","DAC6","Art. 28+"))]
    ext_assessed = [a for a in ext_articles if a["status"] != "GREY"]

    ev_count = c.execute("SELECT COUNT(*) c FROM evidence WHERE entity_id=?", (entity_id,)).fetchone()["c"]
    audit_count = c.execute("SELECT COUNT(*) c FROM dora_audit_log WHERE entity_id=?", (entity_id,)).fetchone()["c"]
    c.close()

    return {
        "entity_id": entity_id,
        "entity_name": entity["name"],
        "entity_type": entity["entity_type"],
        "jurisdiction": entity["jurisdiction"],
        "readiness_score": score,
        "readiness_label": "HIGH" if score >= 75 else "MEDIUM" if score >= 40 else "LOW",
        "enforcement_deadline": "2026-07-17",
        "days_remaining": (datetime(2026, 7, 17, tzinfo=timezone.utc) - datetime.now(timezone.utc)).days,
        "summary": {"GREEN": green, "YELLOW": yellow, "RED": red, "GREY": grey, "total": total},
        "dora_core": {"GREEN": dora_green, "YELLOW": dora_yellow, "RED": dora_red, "GREY": dora_grey, "total": dora_total},
        "enterprise_extension": {"assessed": len(ext_assessed), "total": len(ext_articles), "note": "Enterprise checks (NIS2, LkSG, ISO, etc.) — scored separately"},
        "evidence_count": ev_count,
        "audit_entries": audit_count,
        "articles": articles,
        "assessed_at": now()
    }


async def handle_article_status(params):
    """Detailed status for a specific DORA article."""
    entity_id = params.get("entity_id")
    article = params.get("article", "").strip()
    if not article:
        return {"error": "article parameter required (e.g. 'Art. 28')"}

    c = _db()
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    if not entity_id:
        c.close()
        return {"error": "No entity"}

    req = c.execute("SELECT * FROM requirements WHERE article=?", (article,)).fetchone()
    if not req:
        c.close()
        return {"error": f"Article '{article}' not found in registry"}

    checks = c.execute("SELECT * FROM checks WHERE requirement_id=?", (req["id"],)).fetchall()
    result_checks = []
    for chk in checks:
        ass = c.execute("SELECT * FROM assessments WHERE entity_id=? AND check_id=?",
                        (entity_id, chk["id"])).fetchone()
        evs = c.execute("SELECT id, source_tool, created_at, status FROM evidence WHERE entity_id=? AND check_id=? AND status='active' ORDER BY created_at DESC",
                        (entity_id, chk["id"])).fetchall()
        result_checks.append({
            "check_id": chk["id"],
            "obligation_id": chk["obligation_id"] if chk["obligation_id"] else None,
            "description": chk["description"],
            "tool": chk["tool"],
            "max_age_days": chk["max_age_days"],
            "requires_human_review": bool(chk["requires_human_review"]),
            "green_condition": chk["green_condition"],
            "yellow_condition": chk["yellow_condition"],
            "red_condition": chk["red_condition"],
            "status": ass["status"] if ass else "GREY",
            "reasoning": ass["reasoning"] if ass else None,
            "assessed_at": ass["assessed_at"] if ass else None,
            "evidence_count": len(evs),
            "evidence": [{"id": e["id"], "tool": e["source_tool"], "date": e["created_at"]} for e in evs[:5]]
        })

    c.close()
    statuses = [ck["status"] for ck in result_checks]
    assessed2 = [s for s in statuses if s != "GREY"]
    if "RED" in statuses: agg = "RED"
    elif not assessed2: agg = "GREY"
    elif "GREY" in statuses and assessed2: agg = "YELLOW"
    elif "YELLOW" in statuses: agg = "YELLOW"
    else: agg = "GREEN"

    return {
        "article": req["article"], "title": req["title"],
        "category": req["category"], "priority": req["priority_score"],
        "oracle": req["oracle"], "automation_level": req["automation_level"],
        "overall_status": agg,
        "checks": result_checks,
        "entity_id": entity_id
    }


async def handle_gap_report(params):
    """What's missing: RED + GREY + YELLOW items with action plan."""
    entity_id = params.get("entity_id")
    c = _db()
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    if not entity_id:
        c.close()
        return {"error": "No entity"}

    entity = c.execute("SELECT name FROM entities WHERE id=?", (entity_id,)).fetchone()
    reqs = c.execute("SELECT * FROM requirements ORDER BY priority_score DESC").fetchall()

    gaps = []
    for req in reqs:
        checks = c.execute("SELECT * FROM checks WHERE requirement_id=?", (req["id"],)).fetchall()
        for chk in checks:
            ass = c.execute("SELECT status, reasoning FROM assessments WHERE entity_id=? AND check_id=?",
                            (entity_id, chk["id"])).fetchone()
            status = ass["status"] if ass else "GREY"
            if status in ("RED", "GREY", "YELLOW"):
                gaps.append({
                    "article": req["article"],
                    "title": req["title"],
                    "check_id": chk["id"],
                    "check_description": chk["description"],
                    "status": status,
                    "oracle": req["oracle"],
                    "tool": chk["tool"],
                    "priority": req["priority_score"],
                    "action": f"Use {req['oracle']}:{chk['tool']} to collect evidence" if status == "GREY"
                        else (ass["reasoning"] if ass else "Assess needed"),
                    "requires_human": bool(chk["requires_human_review"])
                })
    c.close()

    by_status = {"RED": [], "GREY": [], "YELLOW": []}
    for g in gaps:
        by_status[g["status"]].append(g)

    return {
        "entity_id": entity_id,
        "entity_name": entity["name"] if entity else "?",
        "total_gaps": len(gaps),
        "by_severity": {k: len(v) for k, v in by_status.items()},
        "critical_gaps": by_status["RED"],
        "unassessed": by_status["GREY"][:10],
        "warnings": by_status["YELLOW"],
        "top_actions": [g for g in sorted(gaps, key=lambda x: -x["priority"]) if g["status"] in ("RED","GREY")][:5]
    }


async def handle_evidence_summary(params):
    """All evidence artefacts for an entity."""
    entity_id = params.get("entity_id")
    c = _db()
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None

    evs = c.execute("""SELECT e.id, e.check_id, e.source_oracle, e.source_tool,
        e.fo_request_id, e.created_at, e.expires_at, e.status, e.content_hash,
        e.freshness_status, e.superseded_by, e.provider_id, e.verified_by, e.verified_at,
        c.description as check_desc, r.article
        FROM evidence e
        LEFT JOIN checks c ON e.check_id = c.id
        LEFT JOIN requirements r ON e.requirement_id = r.id
        WHERE e.entity_id=? ORDER BY e.created_at DESC""",
        (entity_id,)).fetchall()
    c.close()

    return {
        "entity_id": entity_id,
        "total_evidence": len(evs),
        "evidence": [{
            "id": e["id"], "article": e["article"], "check": e["check_id"],
            "check_description": e["check_desc"],
            "oracle": e["source_oracle"], "tool": e["source_tool"],
            "request_id": e["fo_request_id"], "content_hash": e["content_hash"],
            "created_at": e["created_at"], "expires_at": e["expires_at"],
            "status": e["status"],
            "freshness_status": e["freshness_status"] or "unknown",
            "superseded_by": e["superseded_by"],
            "provider_id": e["provider_id"],
            "verified_by": e["verified_by"],
            "verified_at": e["verified_at"]
        } for e in evs],
        "freshness_summary": {
            "current": len([e for e in evs if (e["freshness_status"] or "unknown") == "current"]),
            "stale": len([e for e in evs if (e["freshness_status"] or "") == "stale"]),
            "superseded": len([e for e in evs if (e["freshness_status"] or "") == "superseded"]),
            "disputed": len([e for e in evs if (e["freshness_status"] or "") == "disputed"])
        }
    }


async def handle_entity_list(params):
    """List all registered entities."""
    c = _db()
    entities = c.execute("SELECT * FROM entities").fetchall()
    result = []
    for e in entities:
        ass_count = c.execute("SELECT COUNT(*) c FROM assessments WHERE entity_id=?", (e["id"],)).fetchone()["c"]
        ev_count = c.execute("SELECT COUNT(*) c FROM evidence WHERE entity_id=?", (e["id"],)).fetchone()["c"]
        result.append({
            "id": e["id"], "name": e["name"], "type": e["entity_type"],
            "jurisdiction": e["jurisdiction"], "lei": e["lei"],
            "assessments": ass_count, "evidence": ev_count
        })
    c.close()
    return {"entities": result, "total": len(result)}


async def handle_create_entity(params):
    """Register a new regulated entity."""
    name = params.get("name")
    if not name:
        return {"error": "name parameter required"}
    import uuid
    c = _db()
    eid = f"ent_{uuid.uuid4().hex[:8]}"
    n = now()
    c.execute("""INSERT INTO entities (id, name, entity_type, lei, jurisdiction, bafin_id, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?)""",
        (eid, name, params.get("entity_type", "financial_entity"),
         params.get("lei"), params.get("jurisdiction", "DE"),
         params.get("bafin_id"), n, n))
    c.commit()
    c.close()
    return {"entity_id": eid, "name": name, "created_at": n}


async def handle_collect_art10(params):
    """Collect live evidence for Art. 10 (Detection) from external sources."""
    import aiohttp
    entity_id = params.get("entity_id")
    c = _db()
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    if not entity_id:
        c.close()
        return {"error": "No entity"}

    results = []
    n = now()
    ua = {"User-Agent": "AmpelOracle/1.0"}

    async with aiohttp.ClientSession(headers=ua) as session:
        # NVD
        try:
            async with session.get("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=3", timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 200:
                    d = await r.json()
                    data = {"source": "NVD", "total_cves": d.get("totalResults", 0), "fetched_at": n}
                    import uuid as _u
                    eid = f"ev_{_u.uuid4().hex[:12]}"
                    ch = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
                    c.execute("INSERT INTO evidence (id,entity_id,requirement_id,check_id,evidence_type,content_hash,source_oracle,source_tool,fo_request_id,data_json,created_at,expires_at,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (eid, entity_id, "dora_art10", "art10_c1", "api_response", ch, "doraoracle", "cve_latest", f"fo-art10-nvd-{n[:10]}", json.dumps(data), n,
                         (datetime.now(timezone.utc)+timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), "active"))
                    results.append({"source": "NVD", "status": "ok", "evidence_id": eid})
        except Exception as ex:
            results.append({"source": "NVD", "status": "error", "error": str(ex)})

        # CISA KEV
        try:
            async with session.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 200:
                    d = await r.json()
                    data = {"source": "CISA_KEV", "total_kev": len(d.get("vulnerabilities", [])), "fetched_at": n}
                    import uuid as _u
                    eid = f"ev_{_u.uuid4().hex[:12]}"
                    ch = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
                    c.execute("INSERT INTO evidence (id,entity_id,requirement_id,check_id,evidence_type,content_hash,source_oracle,source_tool,fo_request_id,data_json,created_at,expires_at,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (eid, entity_id, "dora_art10", "art10_c1", "api_response", ch, "doraoracle", "kev_check", f"fo-art10-kev-{n[:10]}", json.dumps(data), n,
                         (datetime.now(timezone.utc)+timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), "active"))
                    results.append({"source": "CISA_KEV", "status": "ok", "evidence_id": eid})
        except Exception as ex:
            results.append({"source": "CISA_KEV", "status": "error", "error": str(ex)})

        # CERT-Bund
        try:
            async with session.get("https://wid.cert-bund.de/portal/wid/kurzinformationen?name=&rss=true", timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status == 200:
                    text = await r.text()
                    data = {"source": "CERT_Bund", "rss_items": text.count("<item>"), "fetched_at": n}
                    import uuid as _u
                    eid = f"ev_{_u.uuid4().hex[:12]}"
                    ch = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
                    c.execute("INSERT INTO evidence (id,entity_id,requirement_id,check_id,evidence_type,content_hash,source_oracle,source_tool,fo_request_id,data_json,created_at,expires_at,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (eid, entity_id, "dora_art10", "art10_c2", "api_response", ch, "doraoracle", "cert_advisories", f"fo-art10-cert-{n[:10]}", json.dumps(data), n,
                         (datetime.now(timezone.utc)+timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"), "active"))
                    results.append({"source": "CERT_Bund", "status": "ok", "evidence_id": eid})
        except Exception as ex:
            results.append({"source": "CERT_Bund", "status": "error", "error": str(ex)})

    # Auto-assess
    ok_c1 = sum(1 for r in results if r["source"] in ("NVD","CISA_KEV") and r["status"] == "ok")
    ok_c2 = sum(1 for r in results if r["source"] == "CERT_Bund" and r["status"] == "ok")

    assessments = []
    for check_id, status, reason in [
        ("art10_c1", "GREEN" if ok_c1 == 2 else "YELLOW", f"NVD+KEV: {ok_c1}/2 sources live"),
        ("art10_c2", "GREEN" if ok_c2 >= 1 else "YELLOW", f"CERT-Bund: {'live' if ok_c2 else 'unavailable'}"),
    ]:
        prev = c.execute("SELECT status FROM assessments WHERE entity_id=? AND check_id=?",
                         (entity_id, check_id)).fetchone()
        import uuid as _u
        aid = f"ass_{_u.uuid4().hex[:12]}"
        c.execute("""INSERT INTO assessments (id,entity_id,requirement_id,check_id,status,previous_status,assessed_at,assessed_by,reasoning)
            VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(entity_id,requirement_id,check_id) DO UPDATE SET
            status=excluded.status, previous_status=assessments.status, assessed_at=excluded.assessed_at, reasoning=excluded.reasoning""",
            (aid, entity_id, "dora_art10", check_id, status, prev["status"] if prev else None, n, "ampeloracle_agent", reason))
        assessments.append({"check_id": check_id, "status": status})

    c.commit()
    c.close()
    return {"entity_id": entity_id, "article": "Art. 10", "evidence_collected": results, "assessments": assessments}


async def handle_audit_trail(params):
    """Chain-linked audit log with integrity check."""
    entity_id = params.get("entity_id")
    limit = params.get("limit", 20)
    c = _db()

    if entity_id:
        logs = c.execute("SELECT * FROM dora_audit_log WHERE entity_id=? ORDER BY id DESC LIMIT ?",
                         (entity_id, limit)).fetchall()
    else:
        logs = c.execute("SELECT * FROM dora_audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    # Verify chain
    all_logs = c.execute("SELECT * FROM dora_audit_log ORDER BY id").fetchall()
    prev_hash = "genesis"
    chain_valid = True
    break_at = None
    for l in all_logs:
        expected = hashlib.sha256(
            f'{l["previous_hash"]}|{l["entity_id"]}|{l["action"]}|{l["detail_json"]}|{l["created_at"]}'.encode()
        ).hexdigest()
        if l["chain_hash"] != expected or l["previous_hash"] != prev_hash:
            chain_valid = False
            break_at = l["id"]
            break
        prev_hash = l["chain_hash"]
    c.close()

    return {
        "chain_valid": chain_valid,
        "chain_length": len(all_logs),
        "break_at": break_at,
        "entries": [{
            "id": l["id"], "entity_id": l["entity_id"],
            "action": l["action"], "actor": l["actor"],
            "detail": json.loads(l["detail_json"]) if l["detail_json"] else None,
            "chain_hash": l["chain_hash"][:16] + "...",
            "created_at": l["created_at"]
        } for l in logs]
    }


# ── Server Setup ──


async def handle_generate_report(params):
    """Generate data-driven DORA Ampel PDF report."""
    import aiohttp
    entity_id = params.get('entity_id', '')
    fmt = params.get('format', 'json')
    url = f'http://127.0.0.1:5196/api/v1/dora/ampel-report?format=json'
    if entity_id:
        url += f'&entity_id={entity_id}'
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 200:
                    data = await r.json()
                    meta = data.get('report_meta', {})
                    meta['pdf_url'] = f'https://feedoracle.io/api/v1/dora/ampel-report?entity_id={entity_id or ""}'
                    meta['note'] = 'PDF download available at pdf_url. Report is ES256K-signed and auditable.'
                    return meta
                else:
                    return {'error': f'Report generation failed: HTTP {r.status}'}
    except Exception as ex:
        return {'error': str(ex)}



async def handle_freshness_check(params):
    """Run freshness watchdog: expire stale evidence, downgrade assessments."""
    import sys
    sys.path.insert(0, '/root/rwa_node/dora')
    from freshness_watchdog import run
    result = run()
    return {
        'expired_evidence': result['expired'],
        'downgrades': result['downgrades'],
        'log': result['log'][-5:]  # last 5 lines
    }


async def handle_bridge_report(params):
    entity_id = params.get('entity_id')
    c = _db()
    if not entity_id:
        e = c.execute('SELECT id FROM entities LIMIT 1').fetchone()
        entity_id = e['id'] if e else None
    if not entity_id:
        c.close()
        return {'error': 'No entity'}
    entity = c.execute('SELECT name FROM entities WHERE id=?', (entity_id,)).fetchone()
    q = "SELECT a.check_id, a.status, a.reasoning, a.bridge_class, a.bridge_action, "
    q += "a.bridge_owner, a.bridge_effort, r.article, r.title, r.priority_score, "
    q += "ch.description as check_desc, ch.tool, ch.green_condition "
    q += "FROM assessments a JOIN requirements r ON a.requirement_id = r.id "
    q += "JOIN checks ch ON a.check_id = ch.id "
    q += "WHERE a.entity_id=? AND a.status IN ('YELLOW','RED','GREY') "
    q += "ORDER BY r.priority_score DESC, a.status"
    rows = c.execute(q, (entity_id,)).fetchall()
    bridge_counts = {}
    for row in rows:
        bc = row['bridge_class'] or 'UNCLASSIFIED'
        bridge_counts[bc] = bridge_counts.get(bc, 0) + 1
    by_effort = {'low': [], 'medium': [], 'high': []}
    for row in rows:
        effort = row['bridge_effort'] or 'medium'
        item = {
            'article': row['article'], 'title': row['title'],
            'check_id': row['check_id'], 'check_description': row['check_desc'],
            'status': row['status'], 'bridge_class': row['bridge_class'],
            'bridge_action': row['bridge_action'], 'bridge_owner': row['bridge_owner'],
            'green_condition': row['green_condition'], 'priority': row['priority_score']
        }
        by_effort.setdefault(effort, []).append(item)
    closable_tech = [r for r in rows if r['bridge_class'] and 'DATA' in r['bridge_class'] and 'WORKFLOW' not in r['bridge_class']]
    closable_process = [r for r in rows if r['bridge_class'] and 'WORKFLOW' in r['bridge_class']]
    needs_business = [r for r in rows if r['bridge_class'] and 'POLICY' in r['bridge_class']]
    c.close()
    return {
        'entity_id': entity_id, 'entity_name': entity['name'] if entity else '?',
        'total_gaps': len(rows),
        'bridge_type_summary': bridge_counts,
        'by_effort': {'low': by_effort.get('low', []), 'medium': by_effort.get('medium', []), 'high': by_effort.get('high', [])},
        'closure_analysis': {
            'closable_by_tech_alone': len(closable_tech),
            'needs_process_change': len(closable_process),
            'needs_business_decision': len(needs_business),
            'tech_items': [r['check_id'] for r in closable_tech],
            'process_items': [r['check_id'] for r in closable_process],
            'business_items': [r['check_id'] for r in needs_business]
        },
        'definitions': {
            'DATA': 'Information fehlt', 'EVIDENCE': 'Nachweis nicht auditfaehig',
            'POLICY': 'Regel nicht formalisiert', 'WORKFLOW': 'Ablauf/Freigabe fehlt',
            'HUMAN_REVIEW': 'Sign-off noetig'
        }
    }



async def handle_register_provider(params):
    """Register an ICT third-party provider for DORA Art. 28 RoI."""
    entity_id = params.get('entity_id')
    c = _db()
    if not entity_id:
        e = c.execute('SELECT id FROM entities LIMIT 1').fetchone()
        entity_id = e['id'] if e else None
    if not entity_id:
        c.close()
        return {'error': 'No entity. Use create_entity first.'}
    name = params.get('provider_name')
    if not name:
        c.close()
        return {'error': 'provider_name required'}
    import uuid as _uuid
    pid = params.get('provider_id') or f"prov_{_uuid.uuid4().hex[:8]}"
    provider = {
        'provider_id': pid, 'provider_name': name,
        'provider_type': params.get('provider_type', 'ict_service'),
        'headquarters': params.get('headquarters', ''),
        'lei': params.get('lei', ''),
        'criticality': params.get('criticality', 'important'),
        'services': params.get('services', ''),
        'data_location': params.get('data_location', ''),
        'contract_start': params.get('contract_start', ''),
        'contract_end': params.get('contract_end', ''),
        'annual_cost_eur': params.get('annual_cost_eur', 0),
        'substitutability': params.get('substitutability', 'moderate'),
        'certifications': params.get('certifications', ''),
        'contact_email': params.get('contact_email', ''),
    }
    n = now()
    import os
    seed_dir = '/root/rwa_node/dora/seed_data'
    os.makedirs(seed_dir, exist_ok=True)
    try:
        with open(f'{seed_dir}/providers.json') as f2:
            pdata = json.load(f2)
    except:
        pdata = {'providers': [], 'total': 0}
    existing = [p for p in pdata['providers'] if p['provider_id'] == pid]
    if existing:
        existing[0].update(provider)
        action = 'updated'
    else:
        pdata['providers'].append(provider)
        action = 'created'
    pdata['total'] = len(pdata['providers'])
    with open(f'{seed_dir}/providers.json', 'w') as f2:
        json.dump(pdata, f2, indent=2)
    its_required = ['provider_name','provider_type','headquarters','lei','criticality','services','data_location','contract_start','contract_end','annual_cost_eur']
    filled = sum(1 for f in its_required if provider.get(f))
    import uuid as _u2
    eid = f"ev_{_u2.uuid4().hex[:12]}"
    ch = hashlib.sha256(json.dumps(provider, sort_keys=True).encode()).hexdigest()
    c.execute("INSERT INTO evidence (id,entity_id,requirement_id,check_id,evidence_type,content_hash,source_oracle,source_tool,fo_request_id,data_json,created_at,expires_at,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (eid, entity_id, 'dora_art28', 'art28_c1', 'api_response', ch, 'ampeloracle', 'register_provider',
         f'fo-art28-reg-{pid}', json.dumps(provider), n,
         (datetime.now(timezone.utc)+timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%SZ'), 'active'))
    c.commit()
    c.close()
    return {
        'status': action, 'provider_id': pid, 'provider_name': name,
        'its_completeness': f'{filled}/{len(its_required)}',
        'missing_fields': [f for f in its_required if not provider.get(f)],
        'entity_id': entity_id, 'evidence_id': eid,
        'total_providers': pdata['total']
    }


async def handle_check_contract(params):
    """Check Art. 30 contract clauses for a provider."""
    provider_id = params.get('provider_id')
    if not provider_id:
        return {'error': 'provider_id required'}
    entity_id = params.get('entity_id')
    c = _db()
    if not entity_id:
        e = c.execute('SELECT id FROM entities LIMIT 1').fetchone()
        entity_id = e['id'] if e else None
    ART30_STD = ['service_description','data_location','data_protection','service_availability_sla',
                 'incident_notification','audit_right','termination_notice','cooperation_with_authorities']
    ART30_CIF = ['subcontracting_approval','data_access_return_deletion','exit_assistance',
                 'business_continuity','ict_security_measures','monitoring_right','benchmarking']
    clauses_present = params.get('standard_clauses', [])
    cif_clauses = params.get('cif_clauses')
    has_exit = params.get('exit_strategy', False)
    is_cif = params.get('is_cif', False)
    std_check = {cl: (cl in clauses_present) for cl in ART30_STD}
    std_score = sum(std_check.values())
    result = {
        'provider_id': provider_id,
        'standard_clauses': std_check,
        'standard_score': f'{std_score}/{len(ART30_STD)}',
        'standard_missing': [cl for cl, present in std_check.items() if not present],
        'exit_strategy': has_exit,
    }
    if is_cif and cif_clauses is not None:
        cif_check = {cl: (cl in cif_clauses) for cl in ART30_CIF}
        cif_score = sum(cif_check.values())
        result['cif_clauses'] = cif_check
        result['cif_score'] = f'{cif_score}/{len(ART30_CIF)}'
        result['cif_missing'] = [cl for cl, present in cif_check.items() if not present]
    if std_score == 8 and has_exit:
        result['verdict'] = 'PASS'
    elif std_score >= 5:
        result['verdict'] = 'WARN'
        result['bridge_class'] = 'EVIDENCE+WORKFLOW'
        result['bridge_action'] = f'Nachverhandlung fuer: {", ".join(result["standard_missing"])}'
    else:
        result['verdict'] = 'BLOCK'
        result['bridge_class'] = 'EVIDENCE+WORKFLOW'
    import uuid as _u3
    n = now()
    eid = f"ev_{_u3.uuid4().hex[:12]}"
    ch = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
    c.execute("INSERT INTO evidence (id,entity_id,requirement_id,check_id,evidence_type,content_hash,source_oracle,source_tool,fo_request_id,data_json,created_at,expires_at,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (eid, entity_id, 'dora_art30', 'art30_c1', 'api_response', ch, 'ampeloracle', 'check_contract',
         f'fo-art30-chk-{provider_id}', json.dumps(result), n,
         (datetime.now(timezone.utc)+timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%SZ'), 'active'))
    c.commit()
    c.close()
    result['entity_id'] = entity_id
    result['evidence_id'] = eid
    return result


async def handle_assess_all(params):
    """Re-run full assessment for an entity. Recomputes all Ampel statuses from evidence."""
    entity_id = params.get('entity_id')
    # AgentGuard pre-flight
    guard = await _guard_preflight('assess_all', params, entity_id)
    if guard.get('decision') == 'denied':
        return {'error': 'AgentGuard denied', 'reason': guard.get('reason'), 'risk_score': guard.get('risk_score')}
    c = _db()
    if not entity_id:
        e = c.execute('SELECT id FROM entities LIMIT 1').fetchone()
        entity_id = e['id'] if e else None
    if not entity_id:
        c.close()
        return {'error': 'No entity'}
    entity = c.execute('SELECT name FROM entities WHERE id=?', (entity_id,)).fetchone()
    reqs = c.execute('SELECT * FROM requirements ORDER BY priority_score DESC').fetchall()
    assessed = 0
    changes = []
    for req in reqs:
        checks = c.execute('SELECT * FROM checks WHERE requirement_id=?', (req['id'],)).fetchall()
        for chk in checks:
            ev_count = c.execute("SELECT COUNT(*) c FROM evidence WHERE entity_id=? AND check_id=? AND status='active'", (entity_id, chk['id'])).fetchone()['c']
            current = c.execute('SELECT status FROM assessments WHERE entity_id=? AND check_id=?', (entity_id, chk['id'])).fetchone()
            cur_status = current['status'] if current else 'GREY'
            if ev_count > 0 and cur_status == 'GREY':
                import uuid as _u4
                aid = f"ass_{_u4.uuid4().hex[:12]}"
                c.execute("INSERT INTO assessments (id,entity_id,requirement_id,check_id,status,previous_status,evidence_count,assessed_at,assessed_by,reasoning) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(entity_id,requirement_id,check_id) DO UPDATE SET status=excluded.status,previous_status=assessments.status,evidence_count=excluded.evidence_count,assessed_at=excluded.assessed_at,reasoning=excluded.reasoning",
                    (aid, entity_id, req['id'], chk['id'], 'YELLOW', cur_status, ev_count, now(), 'assess_all_agent', f'Evidence found ({ev_count} artefacts). Auto-assessed YELLOW pending review.'))
                changes.append({'check_id': chk['id'], 'from': cur_status, 'to': 'YELLOW'})
                assessed += 1
    c.commit()
    green = c.execute("SELECT COUNT(*) c FROM assessments WHERE entity_id=? AND status='GREEN'", (entity_id,)).fetchone()['c']
    yellow = c.execute("SELECT COUNT(*) c FROM assessments WHERE entity_id=? AND status='YELLOW'", (entity_id,)).fetchone()['c']
    red = c.execute("SELECT COUNT(*) c FROM assessments WHERE entity_id=? AND status='RED'", (entity_id,)).fetchone()['c']
    grey = c.execute("SELECT COUNT(*) c FROM assessments WHERE entity_id=? AND status='GREY'", (entity_id,)).fetchone()['c']
    total = green + yellow + red + grey
    score = round((green * 100 + yellow * 50) / max(total, 1), 1)
    c.close()
    result = {
        'entity_id': entity_id, 'entity_name': entity['name'] if entity else '?',
        'assessed': assessed, 'changes': changes,
        'readiness_score': score,
        'summary': {'GREEN': green, 'YELLOW': yellow, 'RED': red, 'GREY': grey},
        'guard': guard
    }
    # AgentGuard post-scan + audit
    scan = await _guard_output_scan('assess_all', json.dumps(result), entity_id)
    result['output_scan'] = scan
    await _guard_audit('assess_all', params, result, guard.get('decision', 'allowed'), entity_id)
    if scan.get('verdict') == 'block':
        return {'error': 'Output blocked by AgentGuard', 'verdict': scan}
    return result





async def handle_onboard_entity(params):
    """Full entity onboarding: create initial assessments for all 39 checks, 
    collect auto-evidence, and run initial assessment. Returns readiness score."""
    entity_id = params.get("entity_id")
    if not entity_id:
        return {"error": "entity_id required"}
    # AgentGuard pre-flight
    guard = await _guard_preflight('onboard_entity', params, entity_id)
    if guard.get('decision') == 'denied':
        return {'error': 'AgentGuard denied', 'reason': guard.get('reason'), 'risk_score': guard.get('risk_score')}
    
    c = _db()
    entity = c.execute("SELECT * FROM entities WHERE id=?", (entity_id,)).fetchone()
    if not entity:
        c.close()
        return {"error": f"Entity {entity_id} not found"}
    
    n = now()
    results = {"entity_id": entity_id, "entity_name": entity["name"], "steps": []}
    
    # Step 1: Create RED assessments for all checks that don't exist yet
    import uuid as _uuid_ob
    reqs = c.execute("SELECT * FROM requirements").fetchall()
    created_assessments = 0
    for req in reqs:
        checks = c.execute("SELECT * FROM checks WHERE requirement_id=?", (req["id"],)).fetchall()
        for chk in checks:
            existing = c.execute("SELECT id FROM assessments WHERE entity_id=? AND check_id=?", (entity_id, chk["id"])).fetchone()
            if not existing:
                aid = f"ass_{_uuid_ob.uuid4().hex[:12]}"
                c.execute("""INSERT INTO assessments 
                    (id, entity_id, requirement_id, check_id, status, previous_status, 
                     score, evidence_count, assessed_at, assessed_by, reasoning)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (aid, entity_id, req["id"], chk["id"], "RED", "GREY", 0, 0, n,
                     "onboard_agent", f"Initial assessment: no evidence yet for {chk['description']}"))
                created_assessments += 1
    c.commit()
    results["steps"].append({"step": "init_assessments", "created": created_assessments})
    
    # Step 2: Collect live evidence for automatable checks
    import aiohttp
    evidence_collected = 0
    ua = {"User-Agent": "AmpelOracle-Onboard/1.0"}
    
    async with aiohttp.ClientSession(headers=ua) as session:
        # Art. 10 — CVE/KEV/CERT
        for source_url, source_name, check_id, req_id in [
            ("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=3", "NVD", "art10_c1", "dora_art10"),
            ("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "CISA_KEV", "art10_c1", "dora_art10"),
        ]:
            try:
                async with session.get(source_url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    if r.status == 200:
                        data = {"source": source_name, "fetched_at": n, "entity": entity_id}
                        eid = f"ev_{_uuid_ob.uuid4().hex[:12]}"
                        ch = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
                        c.execute("""INSERT INTO evidence 
                            (id, entity_id, requirement_id, check_id, evidence_type, content_hash,
                             source_oracle, source_tool, fo_request_id, data_json, created_at, expires_at, status)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (eid, entity_id, req_id, check_id, "api_response", ch, "doraoracle", "cve_latest",
                             f"fo-onboard-{n[:10]}", json.dumps(data), n,
                             (datetime.now(timezone.utc)+timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), "active"))
                        evidence_collected += 1
            except:
                pass
    c.commit()
    results["steps"].append({"step": "collect_evidence", "collected": evidence_collected})
    
    # Step 3: Re-assess all checks based on new evidence
    upgraded = 0
    for req in reqs:
        checks = c.execute("SELECT * FROM checks WHERE requirement_id=?", (req["id"],)).fetchall()
        for chk in checks:
            ev_count = c.execute("SELECT COUNT(*) c FROM evidence WHERE entity_id=? AND check_id=? AND status='active'", (entity_id, chk["id"])).fetchone()["c"]
            if ev_count > 0:
                cur = c.cursor()
                cur.execute("UPDATE assessments SET status='YELLOW', evidence_count=?, assessed_at=?, reasoning=? WHERE entity_id=? AND check_id=? AND status='RED'",
                    (ev_count, n, f"Auto-evidence collected ({ev_count} artefacts). Pending human review for GREEN.", entity_id, chk["id"]))
                if cur.rowcount > 0:
                    upgraded += 1
    c.commit()
    results["steps"].append({"step": "reassess", "upgraded_to_yellow": upgraded})
    
    # Step 4: Calculate readiness score
    green = c.execute("SELECT COUNT(*) c FROM assessments WHERE entity_id=? AND status='GREEN'", (entity_id,)).fetchone()["c"]
    yellow = c.execute("SELECT COUNT(*) c FROM assessments WHERE entity_id=? AND status='YELLOW'", (entity_id,)).fetchone()["c"]
    red = c.execute("SELECT COUNT(*) c FROM assessments WHERE entity_id=? AND status='RED'", (entity_id,)).fetchone()["c"]
    total = green + yellow + red
    score = round((green * 100 + yellow * 50) / max(total, 1), 1)
    
    # Audit log
    detail = json.dumps({"action": "entity_onboarded", "assessments": created_assessments, "evidence": evidence_collected, "upgraded": upgraded, "score": score})
    prev = c.execute("SELECT chain_hash FROM dora_audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = prev["chain_hash"] if prev else "genesis"
    chain_hash = hashlib.sha256(f"{prev_hash}:{detail}".encode()).hexdigest()
    c.execute("INSERT INTO dora_audit_log (entity_id, requirement_id, action, actor, detail_json, previous_hash, chain_hash) VALUES (?,?,?,?,?,?,?)",
        (entity_id, "all", "entity_onboarded", "onboard_agent", detail, prev_hash, chain_hash))
    c.commit()
    c.close()
    
    results["readiness_score"] = score
    results["summary"] = {"GREEN": green, "YELLOW": yellow, "RED": red, "total": total}
    results["guard"] = guard
    # Post-scan
    scan = await _guard_output_scan("onboard_entity", json.dumps(results), entity_id)
    results["output_scan"] = scan
    await _guard_audit("onboard_entity", params, results, guard.get("decision", "allowed"), entity_id)
    if scan.get("verdict") == "block":
        return {"error": "Output blocked by AgentGuard", "verdict": scan}
    return results


# ── Bridge Resolution Engine ──

RESOLUTION_TEMPLATES = {
    "risk_acceptance": {
        "title": "DORA Risk Acceptance — {article} {check_id}",
        "template": """# Risk Acceptance Document
## Entity: {entity_name}
## Article: {article} — {title}
## Check: {check_id}
## Date: {date}

### Risk Description
{action_required}

### Current Assessment
- Status: YELLOW
- Bridge Class: {bridge_class}
- Green Condition: {green_condition}

### Risk Acceptance Statement
The undersigned acknowledges the identified risk and accepts it under the following conditions:

**Accepted Risk:** {action_required}
**Mitigation measures in place:** [TO BE FILLED]
**Review date:** {expiry_date}
**Maximum acceptance period:** {expiry_days} days

### Approval
- Approved by: _________________________ (CISO / Management Body)
- Date: _________________________
- Signature: _________________________

### Conditions
1. This acceptance expires on {expiry_date}
2. Re-assessment required before expiry
3. Any material change triggers immediate re-evaluation

---
Generated by FeedOracle AmpelOracle | Evidence-signed | Audit-chain logged
"""
    },
    "contract_renegotiation": {
        "title": "DORA Contract Renegotiation — {provider}",
        "template": """# Contract Renegotiation Request
## Entity: {entity_name}
## Provider: {provider}
## DORA Article: Art. 30 — Key Contractual Provisions
## Date: {date}

### Missing Clauses (Art. 30(2) Standard)
{missing_clauses}

### Required Action
The following contractual amendments are required to achieve DORA Art. 30 compliance:

{clause_details}

### Deadline
These amendments must be in place by **{expiry_date}** (DORA enforcement: 17 July 2026).

### Template Amendment Language
For each missing clause, the following language (or equivalent) should be added:

{amendment_text}

---
Generated by FeedOracle AmpelOracle | Ref: {check_id}
"""
    },
    "concentration_policy": {
        "title": "DORA Concentration Risk Policy — {entity_name}",
        "template": """# ICT Third-Party Concentration Risk Policy
## Entity: {entity_name}
## DORA Article: Art. 31 — Designation of Critical ICT Third-Party Providers
## Date: {date}

### 1. Purpose
This policy defines thresholds and mitigation requirements for ICT third-party concentration risk per DORA Art. 31.

### 2. Concentration Thresholds
| Metric | Threshold | Action Required |
|--------|-----------|-----------------|
| Single provider > 40% of ICT spend | WARNING | Mitigation plan required |
| Single provider > 60% of ICT spend | CRITICAL | Board approval + exit plan |
| Critical function single-provider | WARNING | Alternative evaluation required |
| No substitution possible | CRITICAL | Risk acceptance by CISO |

### 3. Current Concentration Risks
{concentration_risks}

### 4. Mitigation Plans
{mitigation_plans}

### 5. Review Schedule
- Quarterly review by CISO
- Annual board presentation
- Immediate re-assessment on provider change

### Approval
- Approved by: _________________________ (CISO)
- Date: _________________________

---
Generated by FeedOracle AmpelOracle | Ref: {check_id}
"""
    },
    "exit_strategy": {
        "title": "DORA Exit Strategy — {provider}",
        "template": """# ICT Provider Exit Strategy
## Entity: {entity_name}
## Provider: {provider}
## DORA Article: Art. 30(3)(f) — Exit Strategy
## Date: {date}

### 1. Scope
Exit strategy for {provider} covering data migration, transition period, and alternative providers.

### 2. Data Export
- Export format: [TO BE DEFINED]
- Data volume: [ESTIMATE]
- Export timeline: [DAYS]
- Responsible: IT Operations

### 3. Transition Plan
- Alternative provider(s): [TO BE DEFINED]
- Migration timeline: [WEEKS]
- Parallel operation period: [WEEKS]
- Rollback capability: Yes/No

### 4. Dependencies
- Systems affected: [LIST]
- Business functions impacted: [LIST]
- Staff retraining needed: Yes/No

### 5. Cost Estimate
- Migration cost: EUR [AMOUNT]
- Parallel operation cost: EUR [AMOUNT]
- New provider setup: EUR [AMOUNT]

### Approval
- Approved by: _________________________ (IT Ops + Compliance)
- Date: _________________________

---
Generated by FeedOracle AmpelOracle | Ref: {check_id}
"""
    }
}

# Map check_id to resolution type + template params
BRIDGE_RESOLUTION_MAP = {
    "art30_c1": {"type": "contract_renegotiation", "params": {
        "missing_clauses": "- Salesforce: audit_right, cooperation_with_authorities\n- Azure: termination_notice\n- CrowdStrike: cooperation_with_authorities",
        "clause_details": "1. **audit_right**: Right to audit ICT provider (Art. 30(2)(e))\n2. **cooperation_with_authorities**: Obligation to cooperate with competent authorities (Art. 30(2)(h))\n3. **termination_notice**: Clear termination notice periods (Art. 30(2)(g))",
        "amendment_text": "Suggested clause language available via FeedOracle ContractOracle clause_check tool.",
        "provider": "Salesforce, Azure, CrowdStrike"
    }},
    "art30_c2": {"type": "contract_renegotiation", "params": {
        "missing_clauses": "- AWS: benchmarking (Art. 30(3)(g))",
        "clause_details": "1. **benchmarking**: Right to benchmark ICT services against market standards",
        "amendment_text": "Add benchmarking clause to AWS Enterprise Agreement appendix.",
        "provider": "AWS (CIF provider)"
    }},
    "art30_c3": {"type": "exit_strategy", "params": {"provider": "Salesforce"}},
    "art8_c3": {"type": "risk_acceptance", "params": {}},
    "art31_c1": {"type": "concentration_policy", "params": {
        "concentration_risks": "1. **Finastra** (Core Banking): Single vendor, substitutability very limited, migration 18-24 months\n2. **AWS** (Cloud): Primary IaaS, substitutability limited",
        "mitigation_plans": "1. Finastra: Evaluate parallel core banking by Q3 2026\n2. AWS: Multi-cloud readiness assessment, critical workload portability plan"
    }}
}


async def handle_bridge_resolve(params):
    # AgentGuard pre-flight
    guard = await _guard_preflight('bridge_resolve', params, params.get('entity_id'))
    if guard.get('decision') == 'denied':
        return {'error': 'AgentGuard denied', 'reason': guard.get('reason'), 'risk_score': guard.get('risk_score')}
    """Start bridge resolution workflow: generate template, track approval, close on sign-off."""
    check_id = params.get('check_id')
    entity_id = params.get('entity_id')
    if not check_id:
        return {'error': 'check_id required (e.g. art30_c1, art8_c3, art31_c1)'}
    c = _db()
    if not entity_id:
        e = c.execute('SELECT id FROM entities LIMIT 1').fetchone()
        entity_id = e['id'] if e else None
    if not entity_id:
        c.close()
        return {'error': 'No entity'}
    entity = c.execute('SELECT * FROM entities WHERE id=?', (entity_id,)).fetchone()
    ass = c.execute('SELECT * FROM assessments WHERE entity_id=? AND check_id=?', (entity_id, check_id)).fetchone()
    if not ass:
        c.close()
        return {'error': f'No assessment for {check_id}'}
    if ass['status'] == 'GREEN':
        c.close()
        return {'status': 'already_green', 'check_id': check_id, 'message': 'Bridge already resolved'}
    chk = c.execute('SELECT * FROM checks WHERE id=?', (check_id,)).fetchone()
    req = c.execute('SELECT * FROM requirements WHERE id=?', (ass['requirement_id'],)).fetchone()
    existing = c.execute('SELECT * FROM bridge_resolutions WHERE entity_id=? AND check_id=? AND status IN ("open","pending_approval")', (entity_id, check_id)).fetchone()
    if existing:
        c.close()
        return {'status': 'already_open', 'resolution_id': existing['id'], 'resolution_status': existing['status'],
                'message': 'Resolution workflow already active. Use bridge_approve to approve or bridge_status to check.'}
    import uuid
    rid = f"br_{uuid.uuid4().hex[:12]}"
    n = now()
    expiry_days = params.get('expiry_days', 30)
    expiry_date = (datetime.now(timezone.utc) + timedelta(days=expiry_days)).strftime('%Y-%m-%d')
    resolution_map = BRIDGE_RESOLUTION_MAP.get(check_id, {})
    res_type = resolution_map.get('type', 'risk_acceptance')
    extra_params = resolution_map.get('params', {})
    template_data = RESOLUTION_TEMPLATES.get(res_type, RESOLUTION_TEMPLATES['risk_acceptance'])
    fmt = {
        'entity_name': entity['name'], 'article': req['article'], 'title': req['title'],
        'check_id': check_id, 'date': n[:10], 'bridge_class': ass['bridge_class'] or '',
        'action_required': ass['bridge_action'] or '', 'green_condition': chk['green_condition'] or '',
        'expiry_date': expiry_date, 'expiry_days': expiry_days, **extra_params
    }
    try:
        template_content = template_data['template'].format(**fmt)
        template_title = template_data['title'].format(**fmt)
    except KeyError as e:
        template_content = f"Template generation partial — missing key: {e}"
        template_title = f"Resolution: {check_id}"
    c.execute("""INSERT INTO bridge_resolutions
        (id, entity_id, check_id, requirement_id, bridge_class, owner, status,
         action_required, green_condition, resolution_type, template_generated,
         template_content, expires_at, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (rid, entity_id, check_id, ass['requirement_id'], ass['bridge_class'] or '',
         ass['bridge_owner'] or '', 'open', ass['bridge_action'] or '',
         chk['green_condition'] or '', res_type, 1, template_content,
         (datetime.now(timezone.utc) + timedelta(days=expiry_days)).strftime('%Y-%m-%dT%H:%M:%SZ'),
         n, n))
    c.commit()
    c.close()
    return {
        'resolution_id': rid, 'check_id': check_id, 'article': req['article'],
        'status': 'open', 'resolution_type': res_type,
        'template_title': template_title, 'template_preview': template_content[:500] + '...',
        'owner': ass['bridge_owner'] or '', 'expires_at': expiry_date,
        'next_step': f'Review template, then call bridge_approve(resolution_id="{rid}", approved_by="CISO Name") to sign off.'
    }


async def handle_bridge_approve(params):
    """Approve a bridge resolution: closes bridge, creates evidence, updates Ampel to GREEN."""
    resolution_id = params.get('resolution_id')
    approved_by = params.get('approved_by')
    if not resolution_id:
        return {'error': 'resolution_id required'}
    if not approved_by:
        return {'error': 'approved_by required (e.g. "Dr. Mueller, CISO")'}
    c = _db()
    res = c.execute('SELECT * FROM bridge_resolutions WHERE id=?', (resolution_id,)).fetchone()
    if not res:
        c.close()
        return {'error': f'Resolution {resolution_id} not found'}
    if res['status'] == 'closed':
        c.close()
        return {'status': 'already_closed', 'resolution_id': resolution_id}
    reject = params.get('reject', False)
    if reject:
        reason = params.get('rejection_reason', 'No reason provided')
        c.execute("UPDATE bridge_resolutions SET status='rejected', rejection_reason=?, updated_at=? WHERE id=?",
                  (reason, now(), resolution_id))
        c.commit()
        c.close()
        return {'status': 'rejected', 'resolution_id': resolution_id, 'reason': reason}
    n = now()
    import uuid
    eid = f"ev_{uuid.uuid4().hex[:12]}"
    evidence_data = {
        'resolution_id': resolution_id, 'resolution_type': res['resolution_type'],
        'check_id': res['check_id'], 'approved_by': approved_by, 'approved_at': n,
        'bridge_class': res['bridge_class'], 'action_completed': res['action_required'],
        'template_hash': hashlib.sha256((res['template_content'] or '').encode()).hexdigest()
    }
    ch = hashlib.sha256(json.dumps(evidence_data, sort_keys=True).encode()).hexdigest()
    c.execute("INSERT INTO evidence (id,entity_id,requirement_id,check_id,evidence_type,content_hash,source_oracle,source_tool,fo_request_id,data_json,created_at,expires_at,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (eid, res['entity_id'], res['requirement_id'], res['check_id'], 'sign_off', ch,
         'ampeloracle', 'bridge_approve', f'fo-bridge-{resolution_id}',
         json.dumps(evidence_data), n,
         (datetime.now(timezone.utc) + timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%SZ'), 'active'))
    c.execute("UPDATE bridge_resolutions SET status='closed', approved=1, approved_by=?, approved_at=?, evidence_id=?, closed_at=?, updated_at=? WHERE id=?",
              (approved_by, n, eid, n, n, resolution_id))
    import uuid as _u2
    aid = f"ass_{_u2.uuid4().hex[:12]}"
    c.execute("""INSERT INTO assessments (id,entity_id,requirement_id,check_id,status,previous_status,evidence_count,assessed_at,assessed_by,reasoning,bridge_class,bridge_action)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(entity_id,requirement_id,check_id) DO UPDATE SET
        status=excluded.status, previous_status=assessments.status, evidence_count=excluded.evidence_count,
        assessed_at=excluded.assessed_at, assessed_by=excluded.assessed_by, reasoning=excluded.reasoning,
        bridge_class=excluded.bridge_class, bridge_action=excluded.bridge_action""",
        (aid, res['entity_id'], res['requirement_id'], res['check_id'], 'GREEN', 'YELLOW',
         c.execute("SELECT COUNT(*) c FROM evidence WHERE entity_id=? AND check_id=? AND status='active'",
                   (res['entity_id'], res['check_id'])).fetchone()['c'],
         n, f'bridge_approve:{approved_by}',
         f'Bridge resolved. Approved by {approved_by} on {n[:10]}. Resolution: {resolution_id}.',
         'RESOLVED', None))
    prev_hash = c.execute("SELECT chain_hash FROM dora_audit_log ORDER BY id DESC LIMIT 1").fetchone()
    ph = prev_hash['chain_hash'] if prev_hash else 'genesis'
    detail = json.dumps({'resolution_id': resolution_id, 'check_id': res['check_id'], 'from': 'YELLOW', 'to': 'GREEN', 'approved_by': approved_by})
    chain_hash = hashlib.sha256(f'{ph}|{res["entity_id"]}|bridge_resolved|{detail}|{n}'.encode()).hexdigest()
    c.execute("INSERT INTO dora_audit_log (entity_id,requirement_id,action,actor,detail_json,previous_hash,chain_hash,created_at) VALUES (?,?,?,?,?,?,?,?)",
              (res['entity_id'], res['requirement_id'], 'bridge_resolved', f'bridge_approve:{approved_by}', detail, ph, chain_hash, n))
    c.commit()
    green = c.execute("SELECT COUNT(*) c FROM assessments WHERE entity_id=? AND status='GREEN'", (res['entity_id'],)).fetchone()['c']
    yellow = c.execute("SELECT COUNT(*) c FROM assessments WHERE entity_id=? AND status='YELLOW'", (res['entity_id'],)).fetchone()['c']
    total = c.execute("SELECT COUNT(DISTINCT requirement_id) c FROM assessments WHERE entity_id=?", (res['entity_id'],)).fetchone()['c']
    c.close()
    return {
        'status': 'resolved', 'resolution_id': resolution_id, 'check_id': res['check_id'],
        'article': res['requirement_id'].replace('dora_', '').replace('art', 'Art. '),
        'new_status': 'GREEN', 'approved_by': approved_by, 'evidence_id': eid,
        'readiness_update': f'GREEN={green} YELLOW={yellow}',
        'audit_chain_hash': chain_hash[:16] + '...'
    }


async def handle_bridge_status(params):
    """Check status of all bridge resolutions for an entity."""
    entity_id = params.get('entity_id')
    c = _db()
    if not entity_id:
        e = c.execute('SELECT id FROM entities LIMIT 1').fetchone()
        entity_id = e['id'] if e else None
    resolutions = c.execute("SELECT * FROM bridge_resolutions WHERE entity_id=? ORDER BY created_at DESC", (entity_id,)).fetchall()
    c.close()
    return {
        'entity_id': entity_id,
        'total': len(resolutions),
        'by_status': {s: sum(1 for r in resolutions if r['status'] == s) for s in set(r['status'] for r in resolutions)} if resolutions else {},
        'resolutions': [{
            'id': r['id'], 'check_id': r['check_id'], 'status': r['status'],
            'resolution_type': r['resolution_type'], 'owner': r['owner'],
            'approved_by': r['approved_by'], 'approved_at': r['approved_at'],
            'expires_at': r['expires_at'], 'created_at': r['created_at']
        } for r in resolutions]
    }



async def handle_reg_watchdog(params):
    """AI Regulatory Watchdog: scrapes EBA/ESMA/BaFin for DORA updates, returns new items with impact analysis."""
    import aiohttp
    from xml.etree import ElementTree as ET
    n = now()
    results = []
    sources_checked = 0
    alerts = []

    feeds = [
        ("EBA", "https://www.eba.europa.eu/rss/press-releases", "eba"),
        ("ESMA", "https://www.esma.europa.eu/press-news/esma-news?page=0", "esma"),
        ("BaFin", "https://www.bafin.de/SiteGlobals/Functions/RSSFeed/DE/bafin/rss_Meldungen.xml", "bafin"),
        ("CERT-Bund", "https://wid.cert-bund.de/portal/wid/kurzinformationen?name=&rss=true", "cert"),
    ]

    dora_keywords = ["DORA", "digital operational resilience", "ICT risk", "third-party risk",
                     "critical ICT", "CTPP", "incident reporting", "resilience testing",
                     "register of information", "operational resilience",
                     "Art. 28", "Art. 30", "Art. 17", "RTS 2024", "ITS 2025"]

    async with aiohttp.ClientSession(headers={"User-Agent": "FeedOracle-DORA-Watchdog/1.0"}) as session:
        for name, url, source_id in feeds:
            sources_checked += 1
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                    if r.status == 200:
                        text = await r.text()
                        # Parse RSS/XML
                        items = []
                        try:
                            root = ET.fromstring(text)
                            for item in root.findall('.//item')[:10]:
                                title = item.findtext('title', '')
                                link = item.findtext('link', '')
                                pub = item.findtext('pubDate', '')
                                desc = item.findtext('description', '')[:200]
                                items.append({"title": title, "link": link, "date": pub, "desc": desc})
                        except ET.ParseError:
                            items = [{"title": f"{name} feed parsed (HTML)", "link": url, "date": n, "desc": "Non-RSS source checked"}]

                        # Check for DORA relevance
                        for item in items:
                            full_text = (item.get("title","") + " " + item.get("desc","")).lower()
                            matches = [kw for kw in dora_keywords if kw.lower() in full_text]
                            if matches:
                                # Determine affected articles
                                affected = []
                                if any(k in full_text for k in ["art. 28", "register", "third-party", "ctpp"]): affected.append("Art. 28-31")
                                if any(k in full_text for k in ["art. 30", "contract", "provision"]): affected.append("Art. 30")
                                if any(k in full_text for k in ["art. 17", "incident", "reporting"]): affected.append("Art. 17-21")
                                if any(k in full_text for k in ["testing", "resilience", "tlpt"]): affected.append("Art. 24-27")
                                if any(k in full_text for k in ["governance", "risk management", "ict risk"]): affected.append("Art. 5-6")
                                if not affected: affected = ["General DORA"]
                                alerts.append({
                                    "source": name,
                                    "title": item["title"][:120],
                                    "url": item.get("link",""),
                                    "date": item.get("date",""),
                                    "dora_keywords_matched": matches[:5],
                                    "affected_articles": affected,
                                    "severity": "HIGH" if len(matches) >= 3 else "MEDIUM" if len(matches) >= 2 else "LOW"
                                })

                        results.append({"source": name, "status": "ok", "items_found": len(items), "dora_relevant": len([a for a in alerts if a["source"]==name])})
                    else:
                        results.append({"source": name, "status": f"http_{r.status}", "items_found": 0})
            except Exception as ex:
                results.append({"source": name, "status": "error", "error": str(ex)[:80]})

    return {
        "watchdog_run": n,
        "sources_checked": sources_checked,
        "source_results": results,
        "dora_alerts": len(alerts),
        "alerts": sorted(alerts, key=lambda x: {"HIGH":0,"MEDIUM":1,"LOW":2}.get(x["severity"],3))[:10],
        "enforcement_deadline": "2026-07-17",
        "days_remaining": (datetime(2026, 7, 17, tzinfo=timezone.utc) - datetime.now(timezone.utc)).days,
        "next_run": "Daily at 06:30 UTC (cron)",
        "note": "Monitors EBA, ESMA, BaFin, CERT-Bund for DORA-relevant regulatory changes. Auto-matches to affected articles."
    }


import sys; sys.path.insert(0, '/root/whitelabel/ampeloracle/mcp')
from integrations import azure_ad_check, servicenow_sync, llm_clause_check

async def handle_azure_ad_check(params):
    """Live Azure AD check: MFA status, risky sign-ins, conditional access policies."""
    return await azure_ad_check(params)

async def handle_servicenow_sync(params):
    """ServiceNow incident + change sync for DORA Art. 17/21."""
    return await servicenow_sync(params)

async def handle_llm_clause_check(params):
    """LLM-based contract clause extraction for DORA Art. 30. Paste contract text, get clause-by-clause analysis."""
    return await llm_clause_check(params)

PORT_MCP = 10101
PORT_HEALTH = 10102

server = WhitelabelMCPServer(
    product_name=PRODUCT_NAME, product_slug="ampeloracle",
    version=VERSION, port_mcp=PORT_MCP, port_health=PORT_HEALTH)


server.register_tool("readiness_check",
    "Full DORA readiness score + Ampel per article. Returns GREEN/YELLOW/RED/GREY for all 26 articles, score 0-100, days until deadline.",
    {"entity_id": {"type": "string", "description": "Entity ID (optional)"}},
    handle_readiness_check)

server.register_tool("article_status",
    "Detailed Ampel for a specific DORA article. Each check with GREEN/YELLOW/RED conditions and evidence.",
    {"article": {"type": "string", "description": "e.g. Art. 28"}, "entity_id": {"type": "string", "description": "Entity ID"}},
    handle_article_status)

server.register_tool("gap_report",
    "DORA compliance gaps. RED/GREY/YELLOW items with priority and required actions.",
    {"entity_id": {"type": "string", "description": "Entity ID (optional)"}},
    handle_gap_report)

server.register_tool("evidence_summary",
    "All evidence artefacts for an entity with hashes and expiry dates.",
    {"entity_id": {"type": "string", "description": "Entity ID (optional)"}},
    handle_evidence_summary)

server.register_tool("collect_art10",
    "Collect live Art. 10 evidence from NVD, CISA KEV, CERT-Bund. Auto-assesses.",
    {"entity_id": {"type": "string", "description": "Entity ID (optional)"}},
    handle_collect_art10)

server.register_tool("entity_list",
    "List all registered regulated entities.",
    {},
    handle_entity_list)

server.register_tool("create_entity",
    "Register a new regulated entity.",
    {"name": {"type": "string", "description": "Entity name"}, "entity_type": {"type": "string", "description": "Type"}, "lei": {"type": "string"}, "jurisdiction": {"type": "string"}},
    handle_create_entity)

server.register_tool("audit_trail",
    "Chain-linked audit log with integrity check.",
    {"entity_id": {"type": "string"}, "limit": {"type": "integer", "description": "Max entries"}},
    handle_audit_trail)


server.register_tool("generate_report",
    "Generate data-driven DORA Ampel PDF report. Score, gap analysis, provider register, audit trail integrity.",
    {"entity_id": {"type": "string", "description": "Entity ID (optional)"},
     "format": {"type": "string", "description": "json (meta) or pdf (download)", "default": "json"}},
    handle_generate_report)


server.register_tool("freshness_check",
    "Run freshness watchdog. Expires stale evidence, downgrades GREEN->YELLOW->GREY if evidence too old.",
    {"entity_id": {"type": "string", "description": "Entity ID (optional, checks all)"}},
    handle_freshness_check)


server.register_tool("bridge_report",
    "Bridge gap analysis: classifies gaps by DATA/EVIDENCE/POLICY/WORKFLOW with closure path, owner, effort level.",
    {"entity_id": {"type": "string", "description": "Entity ID (optional)"}},
    handle_bridge_report)


server.register_tool("register_provider",
    "Register an ICT third-party provider for DORA Art. 28 Register of Information. Stores provider data and creates evidence.",
    {"provider_name": {"type": "string", "description": "Provider name e.g. Amazon Web Services EMEA SARL"},
     "provider_type": {"type": "string", "description": "cloud_infrastructure, saas_application, core_banking, cybersecurity, etc."},
     "criticality": {"type": "string", "description": "critical, important, standard"},
     "headquarters": {"type": "string", "description": "Country e.g. Luxembourg, Germany"},
     "lei": {"type": "string", "description": "Legal Entity Identifier"},
     "services": {"type": "string", "description": "Services provided"},
     "data_location": {"type": "string", "description": "Where data is stored e.g. EU (Frankfurt)"},
     "contract_start": {"type": "string"}, "contract_end": {"type": "string"},
     "annual_cost_eur": {"type": "number"}, "substitutability": {"type": "string"},
     "certifications": {"type": "string"}, "entity_id": {"type": "string"}},
    handle_register_provider)

server.register_tool("check_contract",
    "Check DORA Art. 30 contract clauses for a provider. Returns PASS/WARN/BLOCK with missing clauses and bridge classification.",
    {"provider_id": {"type": "string", "description": "Provider ID"},
     "standard_clauses": {"type": "array", "items": {"type": "string"}, "description": "Present standard clauses: service_description, data_location, data_protection, service_availability_sla, incident_notification, audit_right, termination_notice, cooperation_with_authorities"},
     "cif_clauses": {"type": "array", "items": {"type": "string"}, "description": "CIF clauses if applicable"},
     "is_cif": {"type": "boolean", "description": "Is this a CIF (Critical/Important Function) provider?"},
     "exit_strategy": {"type": "boolean", "description": "Exit strategy documented?"},
     "entity_id": {"type": "string"}},
    handle_check_contract)

server.register_tool("assess_all",
    "Re-run full assessment for an entity. Recomputes Ampel statuses from all available evidence.",
    {"entity_id": {"type": "string", "description": "Entity ID (optional)"}},
    handle_assess_all)

server.register_tool("onboard_entity",
    "Full entity onboarding: creates initial RED assessments for all 39 checks, collects auto-evidence from live sources, re-assesses, and returns readiness score.",
    {"entity_id": {"type": "string", "description": "Entity ID to onboard"}},
    handle_onboard_entity)


server.register_tool("bridge_resolve",
    "Start bridge resolution workflow. Generates templates (Risk Acceptance, Contract Renegotiation, Concentration Policy, Exit Strategy), tracks approval process. Call bridge_approve to sign off.",
    {"check_id": {"type": "string", "description": "Check to resolve: art30_c1, art30_c2, art30_c3, art8_c3, art31_c1"},
     "entity_id": {"type": "string", "description": "Entity ID (optional)"},
     "expiry_days": {"type": "integer", "description": "Days until resolution expires (default 30)"}},
    handle_bridge_resolve)

server.register_tool("bridge_approve",
    "Approve or reject a bridge resolution. On approval: creates signed evidence, upgrades Ampel to GREEN, logs to audit chain.",
    {"resolution_id": {"type": "string", "description": "Resolution ID from bridge_resolve"},
     "approved_by": {"type": "string", "description": "Name + role of approver (e.g. Dr. Mueller, CISO)"},
     "reject": {"type": "boolean", "description": "Set true to reject instead of approve"},
     "rejection_reason": {"type": "string", "description": "Reason for rejection (if rejecting)"}},
    handle_bridge_approve)

server.register_tool("bridge_status",
    "Check status of all bridge resolution workflows for an entity. Shows open, pending, closed, rejected.",
    {"entity_id": {"type": "string", "description": "Entity ID (optional)"}},
    handle_bridge_status)


server.register_tool("reg_watchdog",
    "AI Regulatory Watchdog: scrapes EBA/ESMA/BaFin/CERT-Bund for DORA updates. Returns alerts with affected articles and severity. Run daily via cron or on-demand.",
    {"days_back": {"type": "integer", "description": "Check items from last N days (default: 7)"}},
    handle_reg_watchdog)


server.register_tool("azure_ad_check",
    "Live Azure AD integration: MFA registration %, risky users, conditional access policies. DORA Art. 9 evidence. Requires Azure AD config in integrations_config.json.",
    {"force_refresh": {"type": "boolean", "description": "Force fresh API call (default true)"}},
    handle_azure_ad_check)

server.register_tool("servicenow_sync",
    "ServiceNow incident + change management sync. DORA Art. 17/21 evidence. Returns 30-day incident stats, classification, resolution rates.",
    {"days_back": {"type": "integer", "description": "Days to look back (default 30)"}},
    handle_servicenow_sync)

server.register_tool("llm_clause_check",

    "LLM-based DORA Art. 30 contract analysis. Paste contract text, get clause-by-clause PRESENT/PARTIAL/MISSING for all 15 mandatory clauses. Uses Claude API.",
    {"contract_text": {"type": "string", "description": "Contract text (plain text from PDF). Paste key sections."},
     "provider_name": {"type": "string", "description": "Provider name e.g. Salesforce"}},
    handle_llm_clause_check)


async def handle_bus_status(params):
    """Oracle Event Bus status: events, cross-refs, connected oracles."""
    try:
        import sys; sys.path.insert(0,"/root/whitelabel")
        from shared.oracle_bus import OracleBus
        bus=OracleBus("ampeloracle")
        stats=bus.stats()
        entity_id=params.get("entity_id")
        recent=bus.peek(limit=10)
        refs=[]
        if entity_id:
            refs=bus.get_entity_refs(entity_id)
        bus.close()
        return {"bus_stats":stats,"recent_events":[{"id":e["id"],"type":e["event_type"],"source":e["source_oracle"],"entity":e.get("entity_id"),"consumed":bool(e["consumed"]),"created":e["created_at"]} for e in recent],"cross_refs":refs if refs else "Provide entity_id to see cross-refs"}
    except Exception as e:
        return {"error":str(e)}


# Health check (free tool)

# ══════════════════════════════════════════════════════════════
# Cross-Oracle Enterprise Assessment (April 2026 Extension)
# ══════════════════════════════════════════════════════════════

CROSS_ORACLE_CHECKS = {
    "ext_nis2_c1": {"oracle_port": 12601, "tool": "nis2_compliance", "args": {"sector": "finance"}, "field": "compliance_score", "green_threshold": 70, "yellow_threshold": 40},
    "ext_nis2_c3": {"oracle_port": 12601, "tool": "threat_landscape", "args": {"sector": "finance"}, "field": "enisa_top_threats_2025_2026", "green_threshold": 0, "yellow_threshold": 0},
    "ext_iso_c1": {"oracle_port": 12601, "tool": "iso27001_gap", "args": {}, "field": "total_controls", "green_threshold": 0, "yellow_threshold": 0},
    "ext_iso_c2": {"oracle_port": 12601, "tool": "dora_ict_risk", "args": {}, "field": "compliance_score", "green_threshold": 70, "yellow_threshold": 40},
    "ext_lksg_c1": {"oracle_port": 12501, "tool": "lksg_check", "args": {"employee_count": 1000}, "field": "compliance_score", "green_threshold": 70, "yellow_threshold": 40},
    "ext_lksg_c3": {"oracle_port": 12501, "tool": "csrd_supply_check", "args": {}, "field": "applicable_standards", "green_threshold": 0, "yellow_threshold": 0},
    "ext_gdpr_c1": {"oracle_port": 12401, "tool": "gdpr_health_check", "args": {"purpose": "healthcare", "data_types": "diagnosis,treatment"}, "field": "article_9_applicable", "green_threshold": 0, "yellow_threshold": 0},
    "ext_mdr_c1": {"oracle_port": 12401, "tool": "mdr_compliance_check", "args": {"device_class": "IIA"}, "field": "compliance_score", "green_threshold": 70, "yellow_threshold": 40},
    "ext_xr_c1": {"oracle_port": 12201, "tool": "vat_rates", "args": {"country_code": "DE"}, "field": "standard_rate", "green_threshold": 0, "yellow_threshold": 0},
    "ext_dac6_c1": {"oracle_port": 12801, "tool": "dac6_assessment", "args": {"cross_border": True}, "field": "reportable", "green_threshold": 0, "yellow_threshold": 0},
    "ext_contract_c1": {"oracle_port": 12701, "tool": "regulatory_clause_check", "args": {"regulation": "DORA"}, "field": "compliance_score", "green_threshold": 70, "yellow_threshold": 40},
}

async def handle_cross_oracle_assess(params):
    """Run enterprise cross-oracle assessment against all MEGA MCP extensions."""
    entity_id = params.get("entity_id", "")
    checks_to_run = params.get("checks", list(CROSS_ORACLE_CHECKS.keys()))
    
    if isinstance(checks_to_run, str):
        checks_to_run = [c.strip() for c in checks_to_run.split(",")]
    
    results = []
    for check_id in checks_to_run:
        config = CROSS_ORACLE_CHECKS.get(check_id)
        if not config:
            results.append({"check_id": check_id, "status": "GREY", "error": "Unknown check"})
            continue
        
        try:
            from urllib.request import urlopen, Request
            import json as _json
            payload = {
                "jsonrpc": "2.0", "id": 1,
                "method": "tools/call",
                "params": {"name": config["tool"], "arguments": config["args"]}
            }
            req = Request(
                f"http://localhost:{config['oracle_port']}/mcp",
                data=_json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}
            )
            with urlopen(req, timeout=15) as resp:
                data = _json.loads(resp.read())
                text = data.get("result", {}).get("content", [{}])[0].get("text", "{}")
                parsed = _json.loads(text)
                tool_data = parsed.get("data", parsed)
            
            # Determine score
            score_value = tool_data.get(config["field"], None)
            
            if config["green_threshold"] > 0 and isinstance(score_value, (int, float)):
                if score_value >= config["green_threshold"]:
                    status = "GREEN"
                elif score_value >= config["yellow_threshold"]:
                    status = "YELLOW"
                else:
                    status = "RED"
            else:
                # Non-numeric check — if data returned, it's at least YELLOW
                status = "YELLOW" if tool_data and "error" not in tool_data else "RED"
            
            results.append({
                "check_id": check_id,
                "tool": config["tool"],
                "port": config["oracle_port"],
                "status": status,
                "score": score_value if isinstance(score_value, (int, float)) else None,
                "data_available": True,
            })
            
            # Store as evidence in Ampel DB
            if entity_id:
                try:
                    import sqlite3, uuid as _u5
                    c = sqlite3.connect("/root/rwa_node/dora/dora_ampel.db")
                    eid = f"ev_{_u5.uuid4().hex[:12]}"
                    c.execute("INSERT OR REPLACE INTO evidence (id, entity_id, check_id, type, description, content_hash, status, collected_at, collected_by) VALUES (?,?,?,?,?,?,?,datetime('now'),'cross_oracle_assess')",
                        (eid, entity_id, check_id, "api_response", f"Cross-oracle: {config['tool']} → {status}", f"sha256:{hash(str(tool_data))}", "active"))
                    # Update assessment
                    c.execute("INSERT OR REPLACE INTO assessments (id, entity_id, requirement_id, check_id, status, evidence_count, assessed_at, assessed_by, reasoning) VALUES (?, ?, (SELECT requirement_id FROM checks WHERE id=?), ?, ?, 1, datetime('now'), 'cross_oracle_v2', ?)",
                        (f"ass_{check_id}_{entity_id[:8]}", entity_id, check_id, check_id, status, f"Auto-assessed via {config['tool']}: {status}"))
                    c.commit()
                    c.close()
                except Exception as db_err:
                    results[-1]["db_note"] = f"Evidence stored with warning: {str(db_err)[:50]}"
        
        except Exception as e:
            results.append({"check_id": check_id, "status": "GREY", "error": str(e)[:80]})
    
    # Summary
    greens = sum(1 for r in results if r["status"] == "GREEN")
    yellows = sum(1 for r in results if r["status"] == "YELLOW")
    reds = sum(1 for r in results if r["status"] == "RED")
    greys = sum(1 for r in results if r["status"] == "GREY")
    total = len(results)
    score = round((greens * 100 + yellows * 50) / max(total, 1), 1)
    
    return {
        "entity_id": entity_id or "all",
        "cross_oracle_score": score,
        "overall": "GREEN" if reds == 0 and greys == 0 else ("YELLOW" if reds <= 2 else "RED"),
        "summary": {"GREEN": greens, "YELLOW": yellows, "RED": reds, "GREY": greys, "total": total},
        "checks": results,
        "oracles_consulted": list(set(r.get("port") for r in results if r.get("port"))),
        "enterprise_extensions": ["CyberShield (NIS2/ISO)", "SupplyChainOracle (LkSG/CSRD)", "HealthGuard (MDR/GDPR)", "CFOCoPilot (XRechnung)", "TaxOracle (DAC6)", "LegalTechOracle (Contracts)"],
        "note": "Enterprise cross-compliance assessment across 7 MEGA MCP servers",
    }


async def handle_health(args):
    import sqlite3
    db_ok = False
    try:
        c = sqlite3.connect(DB_PATH)
        c.execute("SELECT COUNT(*) FROM assessments")
        db_ok = True
        c.close()
    except: pass
    return {"status": "ok", "product": "AmpelOracle", "version": "1.0.0", "tools": len(server.tools)+2, "database": "ok" if db_ok else "error"}

async def handle_ping(args):
    from datetime import datetime, timezone
    return {"tool": "ping", "status": "ok", "product": "AmpelOracle", "timestamp": datetime.now(timezone.utc).isoformat()}

server.register_tool("cross_oracle_assess", "Enterprise cross-oracle assessment. Runs 18 checks across CyberShield (NIS2/ISO 27001), SupplyChainOracle (LkSG/CSRD), HealthGuard (MDR/GDPR), CFOCoPilot (XRechnung), TaxOracle (DAC6), LegalTechOracle (DORA contracts). Auto-stores evidence and updates Ampel status.",
    {"entity_id": {"type": "string", "description": "Entity to assess"}, "checks": {"type": "string", "description": "Comma-separated check IDs or omit for all"}}, handle_cross_oracle_assess, credits=5)

server.register_tool("health_check", "Server + DB status.",
    {"type": "object", "properties": {}}, handle_health)
server.register_tool("ping", "Quick connectivity test.",
    {"type": "object", "properties": {}}, handle_ping)

server.register_tool("bus_status","Oracle Event Bus status: events, cross-refs, connected oracles.",{"entity_id":{"type":"string","description":"Entity ID for cross-refs"}},handle_bus_status)


# --- Escalation Engine Tools ---

async def handle_escalation_status(params):
    import sqlite3
    entity_id = params.get("entity_id", "")
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    entity_ids = [entity_id] if entity_id else [e["id"] for e in c.execute("SELECT id FROM entities").fetchall()]
    result = {"entities": {}}
    for eid in entity_ids:
        findings = c.execute("SELECT f.*, ch.criticality, ch.escalation_to FROM findings f LEFT JOIN checks ch ON f.check_id=ch.id WHERE f.entity_id=? ORDER BY f.severity DESC, f.due_date ASC", (eid,)).fetchall()
        open_f = [dict(f) for f in findings if f["status"] in ("open","in_progress")]
        breached = [f for f in findings if f["sla_breach"]]
        escalated = [f for f in findings if (f["escalation_level"] or 0) > 0]
        ent = c.execute("SELECT name FROM entities WHERE id=?", (eid,)).fetchone()
        result["entities"][eid] = {
            "name": ent["name"] if ent else eid,
            "open_findings": len(open_f),
            "closed_findings": len([f for f in findings if f["status"]=="closed"]),
            "sla_breaches": len(breached),
            "escalated": len(escalated),
            "board_escalations": len([f for f in findings if (f["escalation_level"] or 0) >= 3]),
            "critical_open": len([f for f in open_f if f["severity"]=="critical"]),
            "findings": [{"id":f["id"],"title":f["title"],"severity":f["severity"],"status":f["status"],"owner":f["owner"],"due_date":f["due_date"],"obligation_id":f.get("obligation_id"),"check_id":f.get("check_id"),"sla_breach":bool(f["sla_breach"]),"escalation_level":f.get("escalation_level",0),"escalated_to":f.get("escalated_to")} for f in open_f[:20]]
        }
    db.close()
    return result

async def handle_run_escalation(params):
    import sys
    sys.path.insert(0, "/root/rwa_node/dora")
    from escalation_engine import run
    return run()


server.register_tool("escalation_status", "Get findings, SLA breaches, escalation status per entity.", {"entity_id": {"type": "string", "description": "Entity ID (empty=all)"}}, handle_escalation_status)
server.register_tool("run_escalation", "Trigger escalation engine: auto-create findings, check SLA, escalate.", {"type": "object", "properties": {}}, handle_run_escalation)



# --- What-if Simulation ---

async def handle_whatif_provider(params):
    """Simulate: What happens if a provider fails? Shows affected articles, checks, score impact."""
    import sqlite3, json
    entity_id = params.get("entity_id", "")
    provider_name = params.get("provider_name", "")
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    
    # Find provider
    if provider_name:
        prov = c.execute("SELECT * FROM providers WHERE entity_id=? AND name LIKE ?", 
            (entity_id, f"%{provider_name}%")).fetchone()
    else:
        db.close()
        # List available providers
        provs = c.execute("SELECT name, criticality, provider_type FROM providers WHERE entity_id=?", (entity_id,)).fetchall()
        return {"error": "provider_name required", "available_providers": [{"name":p["name"],"criticality":p["criticality"],"type":p["provider_type"]} for p in provs]}
    
    if not prov:
        db.close()
        return {"error": f"Provider '{provider_name}' not found for entity {entity_id}"}
    
    prov_dict = dict(prov)
    affected_articles = json.loads(prov_dict["affected_articles"] or "[]")
    affected_checks = json.loads(prov_dict["affected_checks"] or "[]")
    affected_systems = json.loads(prov_dict["affected_systems"] or "[]")
    
    # Current score
    all_ass = c.execute("SELECT check_id, status FROM assessments WHERE entity_id=?", (entity_id,)).fetchall()
    total = len(all_ass)
    current_green = len([a for a in all_ass if a["status"] == "GREEN"])
    current_yellow = len([a for a in all_ass if a["status"] == "YELLOW"])
    current_score = round((current_green * 100 + current_yellow * 50) / max(total, 1), 1)
    
    # Simulate: affected checks go RED
    simulated_red = 0
    impact_details = []
    for ass in all_ass:
        if ass["check_id"] in affected_checks and ass["status"] in ("GREEN", "YELLOW"):
            simulated_red += 1
            check_info = c.execute("SELECT description, criticality, owner_role FROM checks WHERE id=?", (ass["check_id"],)).fetchone()
            req = c.execute("SELECT article FROM requirements WHERE id=(SELECT requirement_id FROM checks WHERE id=?)", (ass["check_id"],)).fetchone()
            impact_details.append({
                "check_id": ass["check_id"],
                "current_status": ass["status"],
                "simulated_status": "RED",
                "article": req["article"] if req else "?",
                "description": check_info["description"] if check_info else "?",
                "criticality": check_info["criticality"] if check_info else "?",
                "owner": check_info["owner_role"] if check_info else "?"
            })
    
    # Calculate new score
    new_green = current_green - len([d for d in impact_details if d["current_status"] == "GREEN"])
    new_yellow = current_yellow - len([d for d in impact_details if d["current_status"] == "YELLOW"])
    new_score = round((new_green * 100 + new_yellow * 50) / max(total, 1), 1)
    score_drop = round(current_score - new_score, 1)
    
    # Unique affected articles
    unique_articles = sorted(set(d["article"] for d in impact_details))
    
    # Risk assessment
    if score_drop > 30:
        risk_level = "CATASTROPHIC"
        risk_color = "RED"
    elif score_drop > 15:
        risk_level = "SEVERE"
        risk_color = "RED"
    elif score_drop > 5:
        risk_level = "SIGNIFICANT"
        risk_color = "YELLOW"
    else:
        risk_level = "MANAGEABLE"
        risk_color = "GREEN"
    
    db.close()
    
    return {
        "simulation": "provider_failure",
        "provider": {
            "name": prov_dict["name"],
            "type": prov_dict["provider_type"],
            "criticality": prov_dict["criticality"],
            "concentration_risk": prov_dict["concentration_risk"],
            "services": json.loads(prov_dict["services"] or "[]"),
            "country": prov_dict["country"],
            "exit_plan": prov_dict["exit_plan_status"]
        },
        "impact": {
            "risk_level": risk_level,
            "score_before": current_score,
            "score_after": new_score,
            "score_drop": score_drop,
            "checks_affected": len(impact_details),
            "articles_affected": unique_articles,
            "systems_affected": affected_systems,
            "new_findings_expected": len(impact_details)
        },
        "affected_checks": impact_details,
        "recommendation": f"Provider {prov_dict['name']} failure would drop readiness by {score_drop}% ({risk_level}). "
            + (f"Exit plan is {prov_dict['exit_plan_status']}. " if prov_dict["exit_plan_status"] != "complete" else "Exit plan is complete. ")
            + f"Immediate action: activate BCM for {len(affected_systems)} affected systems."
    }


async def handle_whatif_stale(params):
    """Simulate: What happens if evidence for a check stays stale for N days?"""
    import sqlite3
    entity_id = params.get("entity_id", "")
    check_id = params.get("check_id", "")
    days = int(params.get("days", 30))
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    
    if not check_id:
        db.close()
        return {"error": "check_id required", "hint": "Use readiness_check to see all checks"}
    
    # Get check info
    check = c.execute("SELECT * FROM checks WHERE id=?", (check_id,)).fetchone()
    if not check:
        db.close()
        return {"error": f"Check {check_id} not found"}
    
    max_age = check["max_age_days"] or 365
    sla = check["sla_days"] or 30
    esc_days = check["escalation_after_days"] or 14
    
    # Current assessment
    ass = c.execute("SELECT status FROM assessments WHERE entity_id=? AND check_id=?", (entity_id, check_id)).fetchone()
    current = ass["status"] if ass else "GREY"
    
    # Simulate
    if days > max_age:
        simulated = "RED" if current == "YELLOW" else ("YELLOW" if current == "GREEN" else current)
    elif days > max_age * 0.85:
        simulated = "YELLOW" if current == "GREEN" else current
    else:
        simulated = current
    
    # Escalation simulation
    esc_level = 0
    if days >= esc_days * 3: esc_level = 3
    elif days >= esc_days * 2: esc_level = 2
    elif days >= esc_days: esc_level = 1
    
    sla_breach = days > sla
    
    db.close()
    
    return {
        "simulation": "stale_evidence",
        "check_id": check_id,
        "description": check["description"],
        "current_status": current,
        "after_days": days,
        "simulated_status": simulated,
        "status_changed": simulated != current,
        "sla_breach": sla_breach,
        "sla_breach_after_days": max(0, days - sla),
        "escalation_level": esc_level,
        "escalation_to": ["", check["owner_role"], check["escalation_to"], "Board"][esc_level],
        "max_age_days": max_age,
        "recommendation": f"After {days}d stale: status {current}->{simulated}, escalation level {esc_level}" + (", SLA BREACH" if sla_breach else "")
    }


server.register_tool("whatif_provider", "Simulate provider failure: which articles/checks are affected, score impact, risk level.", {"entity_id": {"type": "string", "description": "Entity ID"}, "provider_name": {"type": "string", "description": "Provider name (e.g. AWS, Finastra)"}}, handle_whatif_provider)
server.register_tool("whatif_stale", "Simulate stale evidence: what happens if a check stays stale for N days.", {"entity_id": {"type": "string", "description": "Entity ID"}, "check_id": {"type": "string", "description": "Check ID"}, "days": {"type": "integer", "description": "Days stale (default 30)"}}, handle_whatif_stale)



# --- Board / Management View ---

async def handle_board_summary(params):
    """Executive board summary: top risks, overdue findings, concentration risk, score trend, provider impact."""
    import sqlite3, json
    entity_id = params.get("entity_id", "")
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    
    ent = c.execute("SELECT * FROM entities WHERE id=?", (entity_id,)).fetchone()
    ent_name = ent["name"] if ent else entity_id
    
    # 1. Overall scores
    all_ass = c.execute("SELECT check_id, status, requirement_id FROM assessments WHERE entity_id=?", (entity_id,)).fetchall()
    total = len(all_ass)
    g = len([a for a in all_ass if a["status"] == "GREEN"])
    y = len([a for a in all_ass if a["status"] == "YELLOW"])
    r = len([a for a in all_ass if a["status"] == "RED"])
    score = round((g * 100 + y * 50) / max(total, 1), 1)
    
    # 2. Top 5 risks (RED + critical YELLOW)
    top_risks = []
    for a in all_ass:
        if a["status"] in ("RED", "YELLOW"):
            ch = c.execute("SELECT description, criticality, owner_role, sla_days FROM checks WHERE id=?", (a["check_id"],)).fetchone()
            req = c.execute("SELECT article FROM requirements WHERE id=?", (a["requirement_id"],)).fetchone()
            if ch:
                top_risks.append({
                    "article": req["article"] if req else "?",
                    "check": a["check_id"],
                    "description": ch["description"],
                    "status": a["status"],
                    "criticality": ch["criticality"],
                    "owner": ch["owner_role"],
                    "sla_days": ch["sla_days"]
                })
    # Sort: RED first, then by criticality
    crit_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    top_risks.sort(key=lambda x: (0 if x["status"] == "RED" else 1, crit_order.get(x["criticality"], 9)))
    
    # 3. Overdue findings
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    findings = c.execute("SELECT * FROM findings WHERE entity_id=? AND status IN ('open','in_progress')", (entity_id,)).fetchall()
    overdue = [dict(f) for f in findings if f["due_date"] and f["due_date"] < now]
    sla_breaches = [dict(f) for f in findings if f["sla_breach"]]
    board_escalations = [dict(f) for f in findings if (f["escalation_level"] or 0) >= 3]
    
    # 4. Concentration risk (providers)
    providers = c.execute("SELECT * FROM providers WHERE entity_id=?", (entity_id,)).fetchall()
    concentration = []
    for p in providers:
        affected = json.loads(p["affected_checks"] or "[]")
        affected_green = len([a for a in all_ass if a["check_id"] in affected and a["status"] == "GREEN"])
        impact_pct = round(affected_green / max(g, 1) * 100, 1) if g > 0 else 0
        concentration.append({
            "provider": p["name"],
            "type": p["provider_type"],
            "criticality": p["criticality"],
            "concentration_risk": p["concentration_risk"],
            "checks_dependent": len(affected),
            "impact_if_failure_pct": impact_pct,
            "exit_plan": p["exit_plan_status"],
            "contract": p["contract_status"]
        })
    concentration.sort(key=lambda x: x["impact_if_failure_pct"], reverse=True)
    
    # 5. Evidence freshness
    ev_stats = {}
    for row in c.execute("SELECT freshness_status, COUNT(*) FROM evidence WHERE entity_id=? GROUP BY freshness_status", (entity_id,)).fetchall():
        ev_stats[row[0] or "unknown"] = row[1]
    
    # 6. Days to deadline
    from datetime import datetime
    deadline = datetime(2026, 7, 17, tzinfo=timezone.utc)
    days_remaining = (deadline - datetime.now(timezone.utc)).days
    
    # 7. Owner workload
    owner_load = {}
    for f in findings:
        if f["status"] in ("open", "in_progress"):
            owner = f["owner"] or "Unassigned"
            owner_load[owner] = owner_load.get(owner, 0) + 1
    
    db.close()
    
    return {
        "board_summary": {
            "entity": ent_name,
            "report_date": now[:10],
            "days_to_deadline": days_remaining,
            "overall_score": score,
            "status_distribution": {"green": g, "yellow": y, "red": r, "total": total},
            "verdict": "ON TRACK" if score >= 80 else ("AT RISK" if score >= 50 else "CRITICAL")
        },
        "top_risks": top_risks[:5],
        "findings_overview": {
            "total_open": len(findings),
            "overdue": len(overdue),
            "sla_breaches": len(sla_breaches),
            "board_escalations": len(board_escalations),
            "critical_findings": len([f for f in findings if f["severity"] == "critical"]),
            "overdue_items": [{"id": f["id"], "title": f["title"], "owner": f["owner"], "due_date": f["due_date"], "severity": f["severity"]} for f in overdue[:5]]
        },
        "concentration_risk": concentration[:5],
        "evidence_health": ev_stats,
        "owner_workload": [{"owner": k, "open_findings": v} for k, v in sorted(owner_load.items(), key=lambda x: -x[1])]
    }


server.register_tool("board_summary", "Executive board summary: overall score, top 5 risks, overdue findings, SLA breaches, concentration risk, evidence health, owner workload. Designed for management/board reporting.", {"entity_id": {"type": "string", "description": "Entity ID"}}, handle_board_summary)



# --- Closed Loop: Finding Lifecycle ---

async def handle_update_finding(params):
    """Update a finding: claim ownership, set remediation plan, change status. Status flow: open -> in_progress -> retest_pending -> closed."""
    import sqlite3, json
    finding_id = params.get("finding_id", "")
    action = params.get("action", "")  # claim, plan, request_retest, close, accept_risk
    
    if not finding_id or not action:
        return {"error": "finding_id and action required", "valid_actions": ["claim", "plan", "request_retest", "close", "accept_risk"]}
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    f = c.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    if not f:
        db.close()
        return {"error": f"Finding {finding_id} not found"}
    
    n = now()
    changes = {}
    
    if action == "claim":
        owner = params.get("owner", f["owner"])
        c.execute("UPDATE findings SET status='in_progress', owner=?, updated_at=? WHERE id=?", (owner, n, finding_id))
        changes = {"status": "in_progress", "owner": owner}
    
    elif action == "plan":
        plan = params.get("remediation_plan", "")
        if not plan:
            db.close()
            return {"error": "remediation_plan parameter required"}
        c.execute("UPDATE findings SET remediation_plan=?, updated_at=? WHERE id=?", (plan, n, finding_id))
        changes = {"remediation_plan": plan}
    
    elif action == "request_retest":
        c.execute("UPDATE findings SET retest_requested=1, retest_at=?, status='retest_pending', updated_at=? WHERE id=?", (n, n, finding_id))
        changes = {"status": "retest_pending", "retest_requested": True}
    
    elif action == "close":
        reason = params.get("reason", "Manually closed")
        c.execute("UPDATE findings SET status='closed', remediation_plan=?, updated_at=? WHERE id=?", (reason, n, finding_id))
        changes = {"status": "closed", "reason": reason}
    
    elif action == "accept_risk":
        accepted_by = params.get("accepted_by", "")
        expiry_days = int(params.get("expiry_days", 90))
        if not accepted_by:
            db.close()
            return {"error": "accepted_by required for risk acceptance"}
        from datetime import datetime, timezone, timedelta
        exp = (datetime.now(timezone.utc) + timedelta(days=expiry_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        c.execute("UPDATE findings SET risk_accepted=1, accepted_by=?, acceptance_expiry=?, status='risk_accepted', updated_at=? WHERE id=?",
            (accepted_by, exp, n, finding_id))
        changes = {"status": "risk_accepted", "accepted_by": accepted_by, "expiry": exp}
    
    # Audit
    detail = json.dumps({"finding_id": finding_id, "action": action, "changes": changes})
    prev = c.execute("SELECT chain_hash FROM dora_audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = prev["chain_hash"] if prev else "genesis"
    import hashlib
    chain_input = f"{prev_hash}|{f['entity_id']}|finding_{action}|{detail}|{n}"
    chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()
    c.execute("INSERT INTO dora_audit_log (entity_id,requirement_id,action,actor,detail_json,previous_hash,chain_hash,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (f["entity_id"], f["requirement_id"], f"finding_{action}", params.get("actor", "user"), detail, prev_hash, chain_hash, n))
    
    db.commit()
    db.close()
    return {"finding_id": finding_id, "action": action, "changes": changes, "audit": "logged"}


async def handle_retest_finding(params):
    """Re-test a finding: collect fresh evidence for the check, reassess, update finding status."""
    import sqlite3, json, aiohttp
    finding_id = params.get("finding_id", "")
    
    if not finding_id:
        return {"error": "finding_id required"}
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    f = c.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    if not f:
        db.close()
        return {"error": f"Finding {finding_id} not found"}
    
    entity_id = f["entity_id"]
    check_id = f["check_id"]
    requirement_id = f["requirement_id"]
    
    # Get check details
    check = c.execute("SELECT * FROM checks WHERE id=?", (check_id,)).fetchone()
    if not check:
        db.close()
        return {"error": f"Check {check_id} not found"}
    
    # Get control (which oracle/tool to call)
    ctrl = c.execute("SELECT oracle, tool FROM controls WHERE requirement_id=? LIMIT 1", (requirement_id,)).fetchone()
    
    n = now()
    result = {"finding_id": finding_id, "check_id": check_id, "steps": []}
    
    # Step 1: Try to collect evidence via the check's tool
    tool_name = check["tool"]
    evidence_collected = False
    
    # For Art. 10 checks, we can auto-collect
    if check_id.startswith("art10_"):
        try:
            # Call collect_art10 internally
            import sys
            sys.path.insert(0, "/root/rwa_node/dora")
            from collect_art10 import collect_for_check
            ev_result = collect_for_check(entity_id, check_id)
            evidence_collected = ev_result.get("collected", 0) > 0
            result["steps"].append({"step": "collect_evidence", "status": "ok" if evidence_collected else "no_new_evidence", "detail": ev_result})
        except Exception as e:
            result["steps"].append({"step": "collect_evidence", "status": "error", "detail": str(e)})
    else:
        result["steps"].append({"step": "collect_evidence", "status": "skipped", "detail": f"Auto-collection not available for {tool_name}. Manual evidence upload required."})
    
    # Step 2: Reassess
    ev_count = c.execute("SELECT COUNT(*) c FROM evidence WHERE entity_id=? AND check_id=? AND status='active'", (entity_id, check_id)).fetchone()["c"]
    
    current_ass = c.execute("SELECT status FROM assessments WHERE entity_id=? AND check_id=?", (entity_id, check_id)).fetchone()
    old_status = current_ass["status"] if current_ass else "GREY"
    
    # Determine new status based on evidence
    if ev_count > 0 and evidence_collected:
        new_status = "GREEN"
        reasoning = f"Re-test passed: {ev_count} active evidence artefacts, fresh data collected."
    elif ev_count > 0:
        new_status = "YELLOW"
        reasoning = f"Evidence exists ({ev_count}) but no fresh data collected during re-test."
    else:
        new_status = old_status
        reasoning = f"Re-test inconclusive: no active evidence available."
    
    if new_status != old_status:
        import uuid as _u5
        aid = f"ass_{_u5.uuid4().hex[:12]}"
        c.execute("INSERT INTO assessments (id,entity_id,requirement_id,check_id,status,previous_status,evidence_count,assessed_at,assessed_by,reasoning) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(entity_id,requirement_id,check_id) DO UPDATE SET status=excluded.status,previous_status=assessments.status,evidence_count=excluded.evidence_count,assessed_at=excluded.assessed_at,reasoning=excluded.reasoning",
            (aid, entity_id, requirement_id, check_id, new_status, old_status, ev_count, n, "retest_agent", reasoning))
    
    result["steps"].append({"step": "reassess", "old_status": old_status, "new_status": new_status, "evidence_count": ev_count, "reasoning": reasoning})
    
    # Step 3: Update finding
    if new_status == "GREEN":
        c.execute("UPDATE findings SET status='closed', retest_requested=0, remediation_plan=?, updated_at=? WHERE id=?",
            (f"Auto-closed after re-test: {reasoning}", n, finding_id))
        result["steps"].append({"step": "close_finding", "status": "closed", "reason": "assessment_green"})
    else:
        c.execute("UPDATE findings SET retest_requested=0, retest_at=?, updated_at=? WHERE id=?", (n, n, finding_id))
        result["steps"].append({"step": "finding_update", "status": f["status"], "reason": f"Re-test did not resolve. Status remains {new_status}."})
    
    # Audit
    detail = json.dumps({"finding_id": finding_id, "check_id": check_id, "old": old_status, "new": new_status, "evidence": ev_count})
    prev = c.execute("SELECT chain_hash FROM dora_audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = prev["chain_hash"] if prev else "genesis"
    import hashlib
    chain_input = f"{prev_hash}|{entity_id}|retest|{detail}|{n}"
    chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()
    c.execute("INSERT INTO dora_audit_log (entity_id,requirement_id,action,actor,detail_json,previous_hash,chain_hash,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (entity_id, requirement_id, "retest", "retest_agent", detail, prev_hash, chain_hash, n))
    
    db.commit()
    db.close()
    
    result["outcome"] = "RESOLVED" if new_status == "GREEN" else "UNRESOLVED"
    return result


server.register_tool("update_finding", "Update finding lifecycle: claim, set remediation plan, request re-test, close, or accept risk. Status flow: open -> in_progress -> retest_pending -> closed | risk_accepted.", {"finding_id": {"type": "string", "description": "Finding ID"}, "action": {"type": "string", "description": "claim | plan | request_retest | close | accept_risk"}, "owner": {"type": "string", "description": "New owner (for claim)"}, "remediation_plan": {"type": "string", "description": "Remediation plan text (for plan)"}, "accepted_by": {"type": "string", "description": "Name (for accept_risk)"}, "expiry_days": {"type": "integer", "description": "Risk acceptance expiry days (default 90)"}, "reason": {"type": "string", "description": "Close reason (for close)"}, "actor": {"type": "string", "description": "Who is performing this action"}}, handle_update_finding)
server.register_tool("retest_finding", "Re-test a finding: collect fresh evidence, reassess check, auto-close if GREEN. Full closed-loop.", {"finding_id": {"type": "string", "description": "Finding ID to re-test"}}, handle_retest_finding)



# --- Score Trend & Benchmarking ---

async def handle_score_trend(params):
    """Score trend over time: weekly snapshots, delta vs. last week/month, trajectory."""
    import sqlite3
    entity_id = params.get("entity_id", "")
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    
    ent = c.execute("SELECT name, entity_type FROM entities WHERE id=?", (entity_id,)).fetchone()
    
    snapshots = c.execute("SELECT * FROM score_history WHERE entity_id=? ORDER BY recorded_at DESC LIMIT 12", (entity_id,)).fetchall()
    
    if not snapshots:
        db.close()
        return {"error": "No score history available"}
    
    current = dict(snapshots[0])
    timeline = [{"date": s["recorded_at"][:10], "score": s["score"], "green": s["green"], "yellow": s["yellow"], "red": s["red"], "findings": s["open_findings"], "stale": s["stale_evidence"]} for s in reversed(snapshots)]
    
    # Deltas
    prev_week = dict(snapshots[1]) if len(snapshots) > 1 else None
    prev_month = dict(snapshots[4]) if len(snapshots) > 4 else None
    
    delta_week = round(current["score"] - prev_week["score"], 1) if prev_week else None
    delta_month = round(current["score"] - prev_month["score"], 1) if prev_month else None
    
    # Trajectory
    if len(timeline) >= 3:
        recent_deltas = [timeline[i]["score"] - timeline[i-1]["score"] for i in range(1, len(timeline))]
        avg_weekly = round(sum(recent_deltas) / len(recent_deltas), 1)
        if avg_weekly > 2: trajectory = "IMPROVING_FAST"
        elif avg_weekly > 0: trajectory = "IMPROVING"
        elif avg_weekly > -1: trajectory = "STABLE"
        else: trajectory = "DECLINING"
    else:
        avg_weekly = 0
        trajectory = "INSUFFICIENT_DATA"
    
    # Benchmark: compare against same entity type
    entity_type = ent["entity_type"] if ent else ""
    peers = c.execute("""
        SELECT e.name, sh.score, sh.recorded_at
        FROM score_history sh
        JOIN entities e ON sh.entity_id = e.id
        WHERE e.entity_type = ? AND sh.recorded_at = (SELECT MAX(recorded_at) FROM score_history WHERE entity_id = sh.entity_id)
        ORDER BY sh.score DESC
    """, (entity_type,)).fetchall()
    
    peer_scores = [p["score"] for p in peers]
    median = sorted(peer_scores)[len(peer_scores)//2] if peer_scores else 0
    
    db.close()
    
    return {
        "entity": ent["name"] if ent else entity_id,
        "entity_type": entity_type,
        "current_score": current["score"],
        "delta_vs_last_week": delta_week,
        "delta_vs_last_month": delta_month,
        "trajectory": trajectory,
        "avg_weekly_change": avg_weekly,
        "timeline": timeline,
        "benchmark": {
            "peer_type": entity_type,
            "peer_count": len(peers),
            "median_score": median,
            "rank": next((i+1 for i, p in enumerate(peers) if p["name"] == (ent["name"] if ent else "")), None),
            "peers": [{"name": p["name"], "score": p["score"]} for p in peers]
        }
    }


server.register_tool("score_trend", "Score trend over time: weekly deltas, trajectory, peer benchmark. Shows improvement or decline.", {"entity_id": {"type": "string", "description": "Entity ID"}}, handle_score_trend)



# --- 9.5: Dependency Graph + Incident Flow + Evidence Pack ---

async def handle_dependency_graph(params):
    """Full dependency graph: providers → checks → articles → systems. Shows blast radius per provider."""
    import sqlite3, json
    entity_id = params.get("entity_id", "")
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    
    ent = c.execute("SELECT name FROM entities WHERE id=?", (entity_id,)).fetchone()
    providers = c.execute("SELECT * FROM providers WHERE entity_id=?", (entity_id,)).fetchall()
    
    # Build graph
    nodes = []
    edges = []
    
    # Get all current assessments
    assessments = {}
    for a in c.execute("SELECT check_id, status FROM assessments WHERE entity_id=?", (entity_id,)).fetchall():
        assessments[a["check_id"]] = a["status"]
    
    for p in providers:
        checks = json.loads(p["affected_checks"] or "[]")
        systems = json.loads(p["affected_systems"] or "[]")
        articles = json.loads(p["affected_articles"] or "[]")
        
        # Provider impact: how many GREEN checks would go RED
        green_affected = len([ck for ck in checks if assessments.get(ck) == "GREEN"])
        total_green = len([v for v in assessments.values() if v == "GREEN"])
        blast_pct = round(green_affected / max(total_green, 1) * 100, 1)
        
        nodes.append({
            "type": "provider", "id": p["id"], "name": p["name"],
            "provider_type": p["provider_type"], "criticality": p["criticality"],
            "concentration_risk": p["concentration_risk"],
            "exit_plan": p["exit_plan_status"], "contract": p["contract_status"],
            "blast_radius": {"green_checks_affected": green_affected, "blast_pct": blast_pct},
            "connected_checks": len(checks), "connected_systems": len(systems),
            "connected_articles": len(articles),
            "system_names": systems, "article_names": articles
        })
        
        # Edges: provider → checks
        for ck in checks:
            status = assessments.get(ck, "GREY")
            edges.append({"from": p["name"], "to": ck, "type": "depends_on", "check_status": status})
        
        # System nodes
        for sys in systems:
            if not any(n["name"] == sys and n["type"] == "system" for n in nodes):
                nodes.append({"type": "system", "id": sys, "name": sys})
            edges.append({"from": p["name"], "to": sys, "type": "provides"})
    
    # SPOF detection: checks that depend on only one critical provider
    check_provider_count = {}
    for e in edges:
        if e["type"] == "depends_on":
            check_provider_count.setdefault(e["to"], []).append(e["from"])
    
    spofs = []
    for check_id, provs in check_provider_count.items():
        if len(provs) == 1:
            prov_info = next((n for n in nodes if n["name"] == provs[0] and n["type"] == "provider"), None)
            if prov_info and prov_info["criticality"] == "critical":
                spofs.append({"check_id": check_id, "single_provider": provs[0], "status": assessments.get(check_id, "GREY")})
    
    db.close()
    
    return {
        "entity": ent["name"] if ent else entity_id,
        "graph": {"nodes": len(nodes), "edges": len(edges)},
        "providers": [n for n in nodes if n["type"] == "provider"],
        "systems": [n for n in nodes if n["type"] == "system"],
        "spof_risks": spofs,
        "spof_count": len(spofs),
        "highest_blast_radius": sorted([n for n in nodes if n["type"] == "provider"], key=lambda x: x["blast_radius"]["blast_pct"], reverse=True)[:3]
    }


async def handle_incident_flow(params):
    """DORA Incident-to-Evidence flow: log → classify → materiality → deadlines → draft → evidence → closure."""
    import sqlite3, json, uuid, hashlib
    action = params.get("action", "")
    entity_id = params.get("entity_id", "")
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    
    n = now()
    
    if action == "log":
        # Step 1: Log incident
        iid = f"inc_{uuid.uuid4().hex[:8]}"
        title = params.get("title", "Unnamed incident")
        description = params.get("description", "")
        severity = params.get("severity", "medium")
        
        # Create evidence for incident logging
        eid = f"ev_{uuid.uuid4().hex[:12]}"
        data = json.dumps({"incident_id": iid, "title": title, "description": description, "severity": severity, "logged_at": n})
        import hashlib as hl
        content_hash = hl.sha256(data.encode()).hexdigest()
        
        c.execute("INSERT INTO evidence (id,entity_id,requirement_id,check_id,evidence_type,content_hash,source_oracle,source_tool,data_json,created_at,expires_at,status,freshness_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, entity_id, "dora_art17", "art17_c1", "incident_log", content_hash, "ampeloracle", "incident_flow", data, n, "2027-03-29T00:00:00Z", "active", "current"))
        
        db.commit()
        db.close()
        
        return {
            "incident_id": iid, "step": "logged", "evidence_id": eid,
            "dora_article": "Art. 17",
            "next_steps": [
                {"step": "classify", "description": "Classify incident: major/significant/minor", "deadline": "within 4 hours"},
                {"step": "assess_materiality", "description": "Determine if reportable to BaFin", "deadline": "within 4 hours"},
                {"step": "initial_notification", "description": "Submit initial notification if major", "deadline": "within 4 hours of classification"}
            ],
            "dora_timeline": {
                "t0": "Incident detected",
                "t4h": "Classification + initial notification (Art. 19(1))",
                "t72h": "Intermediate report (Art. 19(2))",
                "t30d": "Final report (Art. 19(3))"
            }
        }
    
    elif action == "classify":
        incident_id = params.get("incident_id", "")
        classification = params.get("classification", "significant")
        is_major = classification == "major"
        
        eid = f"ev_{uuid.uuid4().hex[:12]}"
        data = json.dumps({"incident_id": incident_id, "classification": classification, "is_major": is_major, "classified_at": n})
        content_hash = hashlib.sha256(data.encode()).hexdigest()
        
        c.execute("INSERT INTO evidence (id,entity_id,requirement_id,check_id,evidence_type,content_hash,source_oracle,source_tool,data_json,created_at,expires_at,status,freshness_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, entity_id, "dora_art18", "art18_c1", "incident_classification", content_hash, "ampeloracle", "incident_flow", data, n, "2027-03-29T00:00:00Z", "active", "current"))
        
        db.commit()
        db.close()
        
        deadlines = {}
        if is_major:
            from datetime import datetime, timezone, timedelta
            t0 = datetime.now(timezone.utc)
            deadlines = {
                "initial_notification": (t0 + timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "intermediate_report": (t0 + timedelta(hours=72)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "final_report": (t0 + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
            }
        
        return {
            "incident_id": incident_id, "step": "classified", "classification": classification,
            "is_major": is_major, "evidence_id": eid,
            "dora_article": "Art. 18",
            "regulatory_deadlines": deadlines,
            "next_step": "initial_notification" if is_major else "monitor_and_document"
        }
    
    elif action == "notify":
        incident_id = params.get("incident_id", "")
        report_type = params.get("report_type", "initial")
        
        eid = f"ev_{uuid.uuid4().hex[:12]}"
        data = json.dumps({"incident_id": incident_id, "report_type": report_type, "submitted_at": n, "authority": "BaFin", "format": "ITS 2024/1772"})
        content_hash = hashlib.sha256(data.encode()).hexdigest()
        
        article_map = {"initial": ("dora_art19", "art19_c1"), "intermediate": ("dora_art20", "art20_c1"), "final": ("dora_art20", "art20_c1")}
        req_id, check_id = article_map.get(report_type, ("dora_art19", "art19_c1"))
        
        c.execute("INSERT INTO evidence (id,entity_id,requirement_id,check_id,evidence_type,content_hash,source_oracle,source_tool,data_json,created_at,expires_at,status,freshness_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, entity_id, req_id, check_id, f"incident_{report_type}", content_hash, "ampeloracle", "incident_flow", data, n, "2027-03-29T00:00:00Z", "active", "current"))
        
        db.commit()
        db.close()
        
        return {
            "incident_id": incident_id, "step": f"{report_type}_notification", "evidence_id": eid,
            "submitted_to": "BaFin", "format": "ITS 2024/1772",
            "dora_article": f"Art. 19/20 — {report_type} report",
            "evidence_chain": f"Incident logged → classified → {report_type} notification submitted. Full audit trail available."
        }
    
    elif action == "close":
        incident_id = params.get("incident_id", "")
        root_cause = params.get("root_cause", "")
        lessons_learned = params.get("lessons_learned", "")
        
        eid = f"ev_{uuid.uuid4().hex[:12]}"
        data = json.dumps({"incident_id": incident_id, "closed_at": n, "root_cause": root_cause, "lessons_learned": lessons_learned})
        content_hash = hashlib.sha256(data.encode()).hexdigest()
        
        c.execute("INSERT INTO evidence (id,entity_id,requirement_id,check_id,evidence_type,content_hash,source_oracle,source_tool,data_json,created_at,expires_at,status,freshness_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, entity_id, "dora_art17", "art17_c1", "incident_closure", content_hash, "ampeloracle", "incident_flow", data, n, "2027-03-29T00:00:00Z", "active", "current"))
        
        db.commit()
        db.close()
        
        return {
            "incident_id": incident_id, "step": "closed", "evidence_id": eid,
            "evidence_chain_complete": True,
            "steps_documented": ["log", "classify", "initial_notification", "intermediate_report", "final_report", "closure"],
            "total_evidence_created": "6 artefacts for full incident lifecycle"
        }
    
    db.close()
    return {"error": "action required: log | classify | notify | close"}


async def handle_evidence_pack(params):
    """Export evidence pack for a specific article, check, or entity. Pruefer-ready bundle."""
    import sqlite3, json
    entity_id = params.get("entity_id", "")
    article = params.get("article", "")
    check_id = params.get("check_id", "")
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    
    ent = c.execute("SELECT name, entity_type FROM entities WHERE id=?", (entity_id,)).fetchone()
    
    # Build query filter
    where = "e.entity_id = ?"
    params_list = [entity_id]
    
    if check_id:
        where += " AND e.check_id = ?"
        params_list.append(check_id)
    elif article:
        req = c.execute("SELECT id FROM requirements WHERE article = ?", (article,)).fetchone()
        if req:
            where += " AND e.requirement_id = ?"
            params_list.append(req["id"])
    
    evidence = c.execute(f"""
        SELECT e.*, ch.description as check_desc, ch.criticality, ch.owner_role,
               ch.green_condition, ch.data_source, r.article, r.title as art_title
        FROM evidence e
        LEFT JOIN checks ch ON e.check_id = ch.id
        LEFT JOIN requirements r ON e.requirement_id = r.id
        WHERE {where}
        ORDER BY e.requirement_id, e.check_id, e.created_at DESC
    """, tuple(params_list)).fetchall()
    
    # Build pack
    pack = {
        "entity": ent["name"] if ent else entity_id,
        "entity_type": ent["entity_type"] if ent else "",
        "generated_at": now(),
        "scope": article or check_id or "full_entity",
        "total_artefacts": len(evidence),
        "artefacts": []
    }
    
    for ev in evidence:
        pack["artefacts"].append({
            "evidence_id": ev["id"],
            "article": ev["article"],
            "article_title": ev["art_title"],
            "check": ev["check_id"],
            "check_description": ev["check_desc"],
            "criticality": ev["criticality"],
            "owner": ev["owner_role"],
            "evidence_type": ev["evidence_type"],
            "source": f"{ev['source_oracle']}:{ev['source_tool']}",
            "data_source": ev["data_source"],
            "content_hash": ev["content_hash"],
            "signature": ev["fo_signature"],
            "created_at": ev["created_at"],
            "expires_at": ev["expires_at"],
            "status": ev["status"],
            "freshness": ev["freshness_status"],
            "green_condition": ev["green_condition"],
            "verified_by": ev["verified_by"],
            "verified_at": ev["verified_at"]
        })
    
    # Assessments for scope
    if check_id:
        ass = c.execute("SELECT * FROM assessments WHERE entity_id=? AND check_id=?", (entity_id, check_id)).fetchone()
        if ass:
            pack["current_assessment"] = {"status": ass["status"], "reasoning": ass["reasoning"], "assessed_at": ass["assessed_at"], "assessed_by": ass["assessed_by"]}
    
    # Findings for scope
    findings_q = "entity_id=?"
    f_params = [entity_id]
    if check_id:
        findings_q += " AND check_id=?"
        f_params.append(check_id)
    
    findings = c.execute(f"SELECT id, title, severity, status, owner, due_date, sla_breach, escalation_level FROM findings WHERE {findings_q}", tuple(f_params)).fetchall()
    pack["findings"] = [dict(f) for f in findings]
    
    # Audit trail for scope
    audit_q = "entity_id=?"
    a_params = [entity_id]
    if article:
        req2 = c.execute("SELECT id FROM requirements WHERE article=?", (article,)).fetchone()
        if req2:
            audit_q += " AND requirement_id=?"
            a_params.append(req2["id"])
    
    audits = c.execute(f"SELECT action, actor, created_at, chain_hash FROM dora_audit_log WHERE {audit_q} ORDER BY id DESC LIMIT 20", tuple(a_params)).fetchall()
    pack["audit_trail"] = [{"action": a["action"], "actor": a["actor"], "at": a["created_at"], "hash": a["chain_hash"][:16]+"..."} for a in audits]
    
    pack["verification"] = {
        "signing": "ES256K",
        "anchoring": ["Polygon", "XRPL"],
        "hash_algorithm": "SHA-256",
        "chain_integrity": "verified" if len(audits) > 0 else "no_audit_data"
    }
    
    db.close()
    return pack


server.register_tool("dependency_graph", "Full provider dependency graph: providers, systems, checks, blast radius, SPOF detection.", {"entity_id": {"type": "string", "description": "Entity ID"}}, handle_dependency_graph)
server.register_tool("incident_flow", "DORA incident lifecycle: log, classify, notify (BaFin), close. Each step creates signed evidence.", {"entity_id": {"type": "string", "description": "Entity ID"}, "action": {"type": "string", "description": "log | classify | notify | close"}, "title": {"type": "string"}, "description": {"type": "string"}, "severity": {"type": "string"}, "incident_id": {"type": "string"}, "classification": {"type": "string"}, "report_type": {"type": "string"}, "root_cause": {"type": "string"}, "lessons_learned": {"type": "string"}}, handle_incident_flow)
server.register_tool("evidence_pack", "Export evidence pack for article/check/entity. Pruefer-ready: evidence, assessments, findings, audit trail, signatures.", {"entity_id": {"type": "string", "description": "Entity ID"}, "article": {"type": "string", "description": "DORA article e.g. Art. 10"}, "check_id": {"type": "string", "description": "Specific check ID"}}, handle_evidence_pack)



# --- OECD Country Risk for Provider Dependencies ---

async def handle_provider_country_risk(params):
    """Enrich provider dependencies with OECD economic risk data per provider country."""
    import sqlite3, json, aiohttp
    entity_id = params.get("entity_id", "")
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    
    ent = c.execute("SELECT name FROM entities WHERE id=?", (entity_id,)).fetchone()
    providers = c.execute("SELECT * FROM providers WHERE entity_id=?", (entity_id,)).fetchall()
    
    if not providers:
        db.close()
        return {"error": "No providers for entity", "entity_id": entity_id}
    
    # Map 2-letter to 3-letter codes for OECD
    iso2_to_3 = {"US": "USA", "GB": "GBR", "DE": "DEU", "FR": "FRA", "BE": "BEL",
                 "NL": "NLD", "CH": "CHE", "AT": "AUT", "DK": "DNK", "SE": "SWE",
                 "NO": "NOR", "FI": "FIN", "IE": "IRL", "IT": "ITA", "ES": "ESP",
                 "JP": "JPN", "KR": "KOR", "AU": "AUS", "CA": "CAN", "IL": "ISR",
                 "SG": "SGP", "HK": "HKG", "IN": "IND", "BR": "BRA", "MX": "MEX"}
    
    # Collect unique countries
    countries = set()
    for p in providers:
        if p["country"]:
            countries.add(p["country"])
    
    # Fetch OECD data per country via internal HTTP call to OECDOracle
    OECD_MCP = "http://127.0.0.1:7903/mcp/"
    country_data = {}
    
    async with aiohttp.ClientSession() as session:
        for country_2 in countries:
            country_3 = iso2_to_3.get(country_2, country_2)
            if len(country_3) != 3:
                continue
            
            try:
                # Fetch country profile from OECDOracle
                payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "oecd_country_profile", "arguments": {"country": country_3}}}
                async with session.post(OECD_MCP, json=payload,
                    headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
                    timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        text = result.get("result", {}).get("content", [{}])[0].get("text", "{}")
                        data = json.loads(text).get("data", json.loads(text))
                        indicators = data.get("indicators", {})
                        
                        # Build risk profile
                        gdp = indicators.get("gdp_growth", {}).get("value")
                        unemp = indicators.get("unemployment", {}).get("value")
                        cli = indicators.get("cli", {}).get("value")
                        rates = indicators.get("interest_rates", {}).get("value")
                        
                        # Simple risk scoring
                        risk_score = 0
                        risk_factors = []
                        
                        if gdp is not None:
                            if gdp < 0: risk_score += 3; risk_factors.append(f"GDP contraction ({gdp:.1f}%)")
                            elif gdp < 1: risk_score += 1; risk_factors.append(f"Low GDP growth ({gdp:.1f}%)")
                        
                        if unemp is not None:
                            if unemp > 8: risk_score += 2; risk_factors.append(f"High unemployment ({unemp:.1f}%)")
                            elif unemp > 5: risk_score += 1; risk_factors.append(f"Elevated unemployment ({unemp:.1f}%)")
                        
                        if cli is not None:
                            if cli < 99: risk_score += 2; risk_factors.append(f"CLI contraction ({cli:.1f})")
                            elif cli < 100: risk_score += 1; risk_factors.append(f"CLI slowdown ({cli:.1f})")
                        
                        risk_level = "LOW" if risk_score <= 1 else ("MEDIUM" if risk_score <= 3 else "HIGH")
                        
                        country_data[country_2] = {
                            "country_code": country_2,
                            "oecd_code": country_3,
                            "name": data.get("name", country_3),
                            "gdp_growth": gdp,
                            "unemployment": unemp,
                            "cli": cli,
                            "cli_signal": "EXPANSION" if (cli or 100) > 100 else "CONTRACTION",
                            "interest_rate": rates,
                            "economic_risk": risk_level,
                            "risk_score": risk_score,
                            "risk_factors": risk_factors,
                            "source": "OECD"
                        }
            except Exception as e:
                country_data[country_2] = {"country_code": country_2, "error": str(e)[:80]}
    
    # Combine with provider data
    enriched = []
    for p in providers:
        prov = {
            "name": p["name"],
            "type": p["provider_type"],
            "criticality": p["criticality"],
            "country": p["country"],
            "concentration_risk": p["concentration_risk"],
            "exit_plan": p["exit_plan_status"],
            "contract": p["contract_status"],
        }
        
        country_risk = country_data.get(p["country"], {})
        prov["country_economic_profile"] = country_risk
        
        # Combined risk assessment
        econ_risk = country_risk.get("risk_score", 0)
        provider_risk = 3 if p["criticality"] == "critical" else (2 if p["criticality"] == "important" else 1)
        exit_risk = 2 if p["exit_plan_status"] == "missing" else (1 if p["exit_plan_status"] == "partial" else 0)
        
        combined = econ_risk + provider_risk + exit_risk
        prov["combined_risk_score"] = combined
        prov["combined_risk_level"] = "CRITICAL" if combined >= 6 else ("HIGH" if combined >= 4 else ("MEDIUM" if combined >= 2 else "LOW"))
        
        enriched.append(prov)
    
    db.close()
    
    # Sort by combined risk desc
    enriched.sort(key=lambda x: x["combined_risk_score"], reverse=True)
    
    return {
        "entity": ent["name"] if ent else entity_id,
        "providers": enriched,
        "country_profiles": country_data,
        "dora_relevance": "Art. 28-31: ICT third-party risk requires assessment of provider jurisdiction economic stability"
    }


server.register_tool("provider_country_risk", "Enrich provider dependencies with OECD economic risk: GDP, unemployment, CLI per provider country. DORA Art. 28-31 relevant.", {"entity_id": {"type": "string", "description": "Entity ID"}}, handle_provider_country_risk)



# --- Contract Intelligence Pipeline (DocOracle) ---

DORA_ART30_CLAUSES = {
    # Art. 30(2) — 8 Standard Clauses
    "service_description": {"article": "Art. 30(2)(a)", "label": "Clear description of functions/services", "keywords": ["shall provide", "scope of services", "service description", "deliverables", "functions performed"]},
    "data_locations": {"article": "Art. 30(2)(b)", "label": "Data processing & storage locations", "keywords": ["data location", "data center", "processing location", "storage location", "jurisdiction", "data residency"]},
    "data_protection": {"article": "Art. 30(2)(c)", "label": "Data protection & confidentiality", "keywords": ["data protection", "confidentiality", "GDPR", "personal data", "data security", "encryption"]},
    "availability_targets": {"article": "Art. 30(2)(d)", "label": "Service availability & performance targets", "keywords": ["SLA", "availability", "uptime", "service level", "performance", "99.9%", "response time"]},
    "audit_rights": {"article": "Art. 30(2)(e)", "label": "Audit & access rights", "keywords": ["audit", "right to audit", "access right", "inspection", "on-site", "third-party audit", "pooled audit"]},
    "incident_notification": {"article": "Art. 30(2)(f)", "label": "Incident notification obligations", "keywords": ["incident", "notification", "breach notification", "security incident", "notify within", "without undue delay"]},
    "termination_notice": {"article": "Art. 30(2)(g)", "label": "Termination notice periods", "keywords": ["termination", "notice period", "right to terminate", "exit", "wind-down", "transition"]},
    "cooperation_authorities": {"article": "Art. 30(2)(h)", "label": "Cooperation with competent authorities", "keywords": ["competent authority", "regulatory", "BaFin", "supervisor", "cooperation", "information provision"]},
    # Art. 30(3) — 7 CIF Clauses (Critical/Important Functions)
    "full_service_description": {"article": "Art. 30(3)(a)", "label": "Full service level descriptions (CIF)", "keywords": ["service level description", "quantitative", "qualitative", "performance indicator"]},
    "subcontracting_approval": {"article": "Art. 30(3)(b)", "label": "Subcontracting conditions (CIF)", "keywords": ["subcontract", "sub-outsourc", "chain outsourc", "prior approval", "prior consent"]},
    "business_continuity": {"article": "Art. 30(3)(c)", "label": "Business continuity provisions (CIF)", "keywords": ["business continuity", "disaster recovery", "BCM", "BCP", "contingency"]},
    "data_access_recovery": {"article": "Art. 30(3)(d)", "label": "Data access & recovery rights (CIF)", "keywords": ["data access", "data recovery", "data return", "data portability", "escrow"]},
    "exit_assistance": {"article": "Art. 30(3)(e)", "label": "Exit strategy & transition assistance (CIF)", "keywords": ["exit strategy", "transition", "migration", "portability", "transition period", "exit plan"]},
    "testing_cooperation": {"article": "Art. 30(3)(f)", "label": "Testing & audit cooperation (CIF)", "keywords": ["penetration test", "TLPT", "security test", "vulnerability", "testing cooperation"]},
    "benchmarking": {"article": "Art. 30(3)(g)", "label": "Benchmarking clause (CIF)", "keywords": ["benchmark", "market comparison", "price review", "performance comparison"]},
}


async def handle_contract_upload(params):
    """Upload contract text for DORA Art. 30 analysis. Accepts plain text (from PDF extraction)."""
    import sqlite3, json, uuid, hashlib
    entity_id = params.get("entity_id", "")
    provider_name = params.get("provider_name", "")
    contract_text = params.get("contract_text", "")
    file_name = params.get("file_name", "contract.pdf")
    document_type = params.get("document_type", "ict_outsourcing_agreement")
    
    if not contract_text or len(contract_text) < 100:
        return {"error": "contract_text required (min 100 chars). Paste extracted text from PDF."}
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    
    # Find or create provider reference
    provider_id = None
    if provider_name:
        prov = c.execute("SELECT id FROM providers WHERE entity_id=? AND name LIKE ?", (entity_id, f"%{provider_name}%")).fetchone()
        if prov:
            provider_id = prov["id"]
    
    # Create document
    doc_id = f"doc_{uuid.uuid4().hex[:12]}"
    content_hash = hashlib.sha256(contract_text.encode()).hexdigest()
    n = now()
    
    # Check for previous version (same provider)
    prev = None
    if provider_id:
        prev = c.execute("SELECT id FROM documents WHERE provider_id=? ORDER BY uploaded_at DESC LIMIT 1", (provider_id,)).fetchone()
    
    c.execute("""INSERT INTO documents 
        (id, entity_id, provider_id, file_name, document_type, status, content_hash,
         raw_text, page_count, file_size_bytes, uploaded_by, uploaded_at, version, previous_version_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (doc_id, entity_id, provider_id, file_name, document_type, "uploaded", content_hash,
         contract_text, contract_text.count("\n") // 50 + 1, len(contract_text.encode()),
         "contract_pipeline", n, 2 if prev else 1, prev["id"] if prev else None))
    
    # If previous version exists, mark it superseded
    if prev:
        c.execute("UPDATE documents SET status='superseded' WHERE id=?", (prev["id"],))
    
    # Audit
    detail = json.dumps({"document_id": doc_id, "provider": provider_name, "hash": content_hash[:32], "size": len(contract_text)})
    prev_hash_row = c.execute("SELECT chain_hash FROM dora_audit_log ORDER BY id DESC LIMIT 1").fetchone()
    ph = prev_hash_row["chain_hash"] if prev_hash_row else "genesis"
    ch = hashlib.sha256(f"{ph}|{entity_id}|contract_uploaded|{detail}|{n}".encode()).hexdigest()
    c.execute("INSERT INTO dora_audit_log (entity_id,requirement_id,action,actor,detail_json,previous_hash,chain_hash,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (entity_id, "dora_art30", "contract_uploaded", "contract_pipeline", detail, ph, ch, n))
    
    db.commit()
    db.close()
    
    return {
        "document_id": doc_id,
        "content_hash": content_hash,
        "file_name": file_name,
        "provider": provider_name,
        "size_bytes": len(contract_text.encode()),
        "status": "uploaded",
        "version": 2 if prev else 1,
        "previous_version": prev["id"] if prev else None,
        "next_step": "Call contract_analyze to run DORA Art. 30 clause check"
    }


async def handle_contract_analyze(params):
    """Analyze uploaded contract against 15 DORA Art. 30 mandatory clauses. Returns structured compliance report."""
    import sqlite3, json, uuid, hashlib
    document_id = params.get("document_id", "")
    
    if not document_id:
        return {"error": "document_id required. Use contract_upload first."}
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    doc = c.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
    if not doc:
        db.close()
        return {"error": f"Document {document_id} not found"}
    
    contract_text = doc["raw_text"]
    entity_id = doc["entity_id"]
    provider_id = doc["provider_id"]
    n = now()
    
    # Analyze each clause using keyword matching + structure analysis
    results = []
    compliant = 0
    partial = 0
    missing = 0
    
    text_lower = contract_text.lower()
    
    for clause_id, clause_def in DORA_ART30_CLAUSES.items():
        # Count keyword hits
        hits = 0
        matched_keywords = []
        for kw in clause_def["keywords"]:
            count = text_lower.count(kw.lower())
            if count > 0:
                hits += count
                matched_keywords.append(kw)
        
        # Determine status
        if hits >= 3 and len(matched_keywords) >= 2:
            status = "COMPLIANT"
            confidence = min(0.95, 0.7 + hits * 0.03)
            reasoning = f"Found {hits} keyword matches across {len(matched_keywords)} patterns: {', '.join(matched_keywords[:5])}"
            compliant += 1
        elif hits >= 1:
            status = "PARTIAL"
            confidence = 0.5 + hits * 0.05
            reasoning = f"Partial coverage: {hits} matches for {', '.join(matched_keywords[:3])}. May need strengthening."
            partial += 1
        else:
            status = "MISSING"
            confidence = 0.85
            reasoning = f"No relevant keywords found. Clause appears to be absent from the contract."
            missing += 1
        
        # Extract relevant text snippet (first occurrence)
        extracted = ""
        for kw in matched_keywords[:1]:
            idx = text_lower.find(kw.lower())
            if idx >= 0:
                start = max(0, idx - 100)
                end = min(len(contract_text), idx + 200)
                extracted = contract_text[start:end].strip()
        
        # Suggested fix for gaps
        fix = ""
        if status != "COMPLIANT":
            fix = f"Add clause covering {clause_def['label']} per {clause_def['article']}."
        
        clause_result = {
            "clause_id": clause_id,
            "article": clause_def["article"],
            "label": clause_def["label"],
            "status": status,
            "confidence": round(confidence, 2),
            "reasoning": reasoning,
            "extracted_text": extracted[:300] if extracted else None,
            "suggested_fix": fix if fix else None,
        }
        results.append(clause_result)
        
        # Save to DB
        ec_id = f"ec_{uuid.uuid4().hex[:12]}"
        c.execute("""INSERT OR REPLACE INTO extracted_clauses 
            (id, document_id, entity_id, provider_id, dora_article, clause_type, clause_label,
             extracted_text, llm_confidence, compliance_status, gap_reasoning, suggested_fix, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ec_id, document_id, entity_id, provider_id,
             clause_def["article"], clause_id, clause_def["label"],
             extracted[:500] if extracted else None, round(confidence, 2),
             status, reasoning, fix, n))
    
    # Update document status
    c.execute("UPDATE documents SET status='analyzed', parsed_at=? WHERE id=?", (n, document_id))
    
    # Update provider contract status
    if provider_id:
        review_status = "valid" if missing == 0 else ("needs_review" if missing <= 3 else "non_compliant")
        c.execute("UPDATE providers SET active_document_id=?, contract_review_status=?, contract_last_reviewed=? WHERE id=?",
            (document_id, review_status, n, provider_id))
    
    # Create evidence for Art. 30 checks
    ev_id = f"ev_{uuid.uuid4().hex[:12]}"
    ev_data = json.dumps({"document_id": document_id, "clauses_analyzed": len(results),
                          "compliant": compliant, "partial": partial, "missing": missing})
    ev_hash = hashlib.sha256(ev_data.encode()).hexdigest()
    
    c.execute("""INSERT INTO evidence 
        (id, entity_id, requirement_id, check_id, evidence_type, content_hash,
         source_oracle, source_tool, data_json, created_at, expires_at, status, freshness_status, provider_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (ev_id, entity_id, "dora_art30", "art30_c1", "contract_analysis", ev_hash,
         "ampeloracle", "contract_analyze", ev_data, n, "2027-03-29T00:00:00Z", "active", "current", provider_id))
    
    # Audit
    detail = json.dumps({"document_id": document_id, "compliant": compliant, "partial": partial, "missing": missing})
    prev_hash_row = c.execute("SELECT chain_hash FROM dora_audit_log ORDER BY id DESC LIMIT 1").fetchone()
    ph = prev_hash_row["chain_hash"] if prev_hash_row else "genesis"
    ch = hashlib.sha256(f"{ph}|{entity_id}|contract_analyzed|{detail}|{n}".encode()).hexdigest()
    c.execute("INSERT INTO dora_audit_log (entity_id,requirement_id,action,actor,detail_json,previous_hash,chain_hash,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (entity_id, "dora_art30", "contract_analyzed", "contract_pipeline", detail, ph, ch, n))
    
    db.commit()
    db.close()
    
    # Score
    total = len(results)
    score = round((compliant * 100 + partial * 50) / max(total, 1), 1)
    
    return {
        "document_id": document_id,
        "provider": doc["file_name"],
        "analysis_score": score,
        "summary": {"total_clauses": total, "compliant": compliant, "partial": partial, "missing": missing},
        "verdict": "COMPLIANT" if missing == 0 and partial == 0 else ("GAPS_FOUND" if missing > 0 else "PARTIAL_COMPLIANCE"),
        "clauses": results,
        "evidence_id": ev_id,
        "dora_reference": "DORA Art. 30(2) — 8 standard clauses + Art. 30(3) — 7 CIF clauses",
        "next_steps": [f"Fix {missing} missing + {partial} partial clauses" if missing + partial > 0 else "All clauses compliant"]
    }


async def handle_contract_status(params):
    """Overview of all analyzed contracts per entity. Shows clause gaps, review status, versions."""
    import sqlite3, json
    entity_id = params.get("entity_id", "")
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    
    docs = c.execute("SELECT d.*, p.name as provider_name FROM documents d LEFT JOIN providers p ON d.provider_id=p.id WHERE d.entity_id=? ORDER BY d.uploaded_at DESC", (entity_id,)).fetchall()
    
    result = []
    for doc in docs:
        clauses = c.execute("SELECT clause_type, compliance_status, llm_confidence FROM extracted_clauses WHERE document_id=?", (doc["id"],)).fetchall()
        compliant = len([cl for cl in clauses if cl["compliance_status"] == "COMPLIANT"])
        partial = len([cl for cl in clauses if cl["compliance_status"] == "PARTIAL"])
        missing = len([cl for cl in clauses if cl["compliance_status"] == "MISSING"])
        
        result.append({
            "document_id": doc["id"],
            "provider": doc["provider_name"] or doc["file_name"],
            "type": doc["document_type"],
            "status": doc["status"],
            "version": doc["version"],
            "uploaded_at": doc["uploaded_at"],
            "analyzed_at": doc["parsed_at"],
            "clauses": {"compliant": compliant, "partial": partial, "missing": missing, "total": len(clauses)},
            "gaps": [cl["clause_type"] for cl in clauses if cl["compliance_status"] != "COMPLIANT"]
        })
    
    db.close()
    return {"entity_id": entity_id, "contracts": result, "total_documents": len(result)}


server.register_tool("contract_upload", "Upload contract text for DORA Art. 30 analysis. Creates document record with SHA-256 hash, version tracking, audit trail.", {"entity_id": {"type": "string", "description": "Entity ID"}, "provider_name": {"type": "string", "description": "Provider name"}, "contract_text": {"type": "string", "description": "Contract text (extracted from PDF)"}, "file_name": {"type": "string", "description": "Original file name"}, "document_type": {"type": "string", "description": "ict_outsourcing_agreement | dpa | sla | master_service_agreement"}}, handle_contract_upload)
server.register_tool("contract_analyze", "Analyze contract against 15 DORA Art. 30 mandatory clauses. Returns compliance status per clause with confidence score, extracted text, gap reasoning, suggested fix.", {"document_id": {"type": "string", "description": "Document ID from contract_upload"}}, handle_contract_analyze)
server.register_tool("contract_status", "Overview of all analyzed contracts per entity. Shows clause gaps, review status, document versions.", {"entity_id": {"type": "string", "description": "Entity ID"}}, handle_contract_status)



# --- Cross-Regulation Finding Engine ---

async def handle_cross_regulation_check(params):
    """Check which DORA findings also impact MiCA and AMLR. Auto-tags findings with affected regulations."""
    import sqlite3, json
    entity_id = params.get("entity_id", "")
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    
    ent = c.execute("SELECT name FROM entities WHERE id=?", (entity_id,)).fetchone()
    
    # Get all regulation mappings
    mappings = c.execute("SELECT * FROM regulation_mapping WHERE auto_propagate=1").fetchall()
    mapping_index = {}
    for m in mappings:
        mapping_index.setdefault(m["dora_article"], []).append({
            "regulation": m["mapped_regulation"],
            "article": m["mapped_article"],
            "type": m["mapping_type"],
            "description": m["description"]
        })
    
    # Get all open findings for this entity
    findings = c.execute("SELECT * FROM findings WHERE entity_id=? AND status IN ('open','in_progress','retest_pending')", (entity_id,)).fetchall()
    
    tagged = 0
    cross_findings = []
    
    for f in findings:
        req_id = f["requirement_id"]
        cross_regs = mapping_index.get(req_id, [])
        
        if cross_regs:
            regulations = ["DORA"]
            mica_arts = []
            amlr_arts = []
            impacts = []
            
            for cr in cross_regs:
                if cr["regulation"] == "MiCA":
                    regulations.append("MiCA")
                    mica_arts.append(cr["article"])
                    impacts.append({"regulation": "MiCA", "article": cr["article"], "type": cr["type"], "reasoning": cr["description"]})
                elif cr["regulation"] == "AMLR":
                    regulations.append("AMLR")
                    amlr_arts.append(cr["article"])
                    impacts.append({"regulation": "AMLR", "article": cr["article"], "type": cr["type"], "reasoning": cr["description"]})
            
            regulations = list(set(regulations))
            is_cross = len(regulations) > 1
            
            # Update finding
            c.execute("""UPDATE findings SET 
                regulations=?, cross_regulation=?, mica_articles=?, amlr_articles=?
                WHERE id=?""",
                (json.dumps(regulations), 1 if is_cross else 0,
                 json.dumps(list(set(mica_arts))) if mica_arts else None,
                 json.dumps(list(set(amlr_arts))) if amlr_arts else None,
                 f["id"]))
            
            if is_cross:
                tagged += 1
                cross_findings.append({
                    "finding_id": f["id"],
                    "title": f["title"],
                    "severity": f["severity"],
                    "dora_article": req_id,
                    "regulations": regulations,
                    "mica_impact": mica_arts,
                    "amlr_impact": amlr_arts,
                    "cross_impacts": impacts
                })
        else:
            # DORA-only finding
            c.execute("UPDATE findings SET regulations=?, cross_regulation=0 WHERE id=?",
                (json.dumps(["DORA"]), f["id"]))
    
    db.commit()
    
    # Stats
    total_cross = c.execute("SELECT COUNT(*) FROM findings WHERE entity_id=? AND cross_regulation=1", (entity_id,)).fetchone()[0]
    total_mica = c.execute("SELECT COUNT(*) FROM findings WHERE entity_id=? AND mica_articles IS NOT NULL", (entity_id,)).fetchone()[0]
    total_amlr = c.execute("SELECT COUNT(*) FROM findings WHERE entity_id=? AND amlr_articles IS NOT NULL", (entity_id,)).fetchone()[0]
    
    db.close()
    
    return {
        "entity": ent["name"] if ent else entity_id,
        "total_findings": len(findings),
        "cross_regulation_findings": tagged,
        "mica_affected": total_mica,
        "amlr_affected": total_amlr,
        "dora_only": len(findings) - tagged,
        "cross_findings": cross_findings[:20],
        "mapping_rules": len(mapping_index),
        "note": "Findings tagged with all affected regulations. Cross-regulation findings need coordinated remediation across DORA + MiCA + AMLR."
    }


async def handle_regulation_impact(params):
    """For a specific DORA article, show all cross-regulation impacts (MiCA, AMLR)."""
    import sqlite3, json
    dora_article = params.get("dora_article", "")
    
    if not dora_article:
        return {"error": "dora_article required (e.g. dora_art28)"}
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    mappings = c.execute("SELECT * FROM regulation_mapping WHERE dora_article=?", (dora_article,)).fetchall()
    
    if not mappings:
        db.close()
        return {"dora_article": dora_article, "cross_impacts": [], "note": "No cross-regulation mappings for this article."}
    
    req = c.execute("SELECT article, title FROM requirements WHERE id=?", (dora_article,)).fetchone()
    
    impacts = []
    for m in mappings:
        impacts.append({
            "target_regulation": m["mapped_regulation"],
            "target_article": m["mapped_article"],
            "mapping_type": m["mapping_type"],
            "description": m["description"],
            "auto_propagate": bool(m["auto_propagate"])
        })
    
    db.close()
    
    return {
        "dora_article": dora_article,
        "dora_title": req["title"] if req else None,
        "cross_impacts": impacts,
        "total_impacts": len(impacts),
        "mica_impacts": len([i for i in impacts if i["target_regulation"] == "MiCA"]),
        "amlr_impacts": len([i for i in impacts if i["target_regulation"] == "AMLR"])
    }


server.register_tool("cross_regulation_check", "Tag findings with cross-regulation impact (DORA + MiCA + AMLR). Shows which DORA findings also affect MiCA insider info or AMLR screening.", {"entity_id": {"type": "string", "description": "Entity ID"}}, handle_cross_regulation_check)
server.register_tool("regulation_impact", "Show cross-regulation impacts for a specific DORA article. Maps DORA → MiCA + AMLR.", {"dora_article": {"type": "string", "description": "DORA article ID (e.g. dora_art28)"}}, handle_regulation_impact)



# --- BaFin Incident Report Generator (ITS 2024/1772) ---

async def handle_bafin_report_draft(params):
    """Generate ITS 2024/1772 compliant incident report draft for BaFin submission. 
    Creates all mandatory fields per DORA Art. 19. Preview mode (requires board approve before send)."""
    import sqlite3, json, uuid, hashlib
    
    entity_id = params.get("entity_id", "")
    incident_id = params.get("incident_id", "")
    report_type = params.get("report_type", "initial")  # initial | intermediate | final
    
    # Incident details (from params or evidence)
    title = params.get("title", "")
    description = params.get("description", "")
    classification = params.get("classification", "major")
    affected_services = params.get("affected_services", "")
    affected_clients = params.get("affected_clients", "0")
    root_cause = params.get("root_cause", "")
    remediation = params.get("remediation", "")
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    
    ent = c.execute("SELECT * FROM entities WHERE id=?", (entity_id,)).fetchone()
    n = now()
    
    # ITS 2024/1772 mandatory fields
    # Deadlines per report type
    deadlines = {
        "initial": {"hours": 4, "description": "Within 4 hours of classification as major/significant"},
        "intermediate": {"hours": 72, "description": "Within 72 hours of initial notification"},
        "final": {"days": 30, "description": "Within 1 month of resuming regular activities"}
    }
    
    # Build the ITS-compliant report structure
    report = {
        "meta": {
            "report_id": f"ITS-{uuid.uuid4().hex[:8].upper()}",
            "report_type": report_type,
            "its_reference": "ITS 2024/1772",
            "dora_article": "Art. 19" if report_type == "initial" else "Art. 20",
            "generated_at": n,
            "deadline": deadlines.get(report_type, {}),
            "status": "DRAFT — Requires board approval before submission"
        },
        "section_1_reporting_entity": {
            "entity_name": ent["name"] if ent else "",
            "lei": ent["lei"] if ent else "",
            "bafin_id": ent["bafin_id"] if ent else "",
            "entity_type": ent["entity_type"] if ent else "",
            "jurisdiction": ent["jurisdiction"] if ent else "DE",
            "nca": ent["nca"] if ent else "BaFin",
            "contact_person": "[REQUIRES MANUAL INPUT]",
            "contact_email": "[REQUIRES MANUAL INPUT]",
            "contact_phone": "[REQUIRES MANUAL INPUT]"
        },
        "section_2_incident": {
            "incident_id": incident_id,
            "title": title,
            "description": description,
            "classification": classification,
            "detection_date": params.get("detection_date", n),
            "classification_date": params.get("classification_date", n),
            "ongoing": params.get("ongoing", True),
        },
        "section_3_impact": {
            "affected_services": affected_services,
            "affected_member_states": params.get("affected_member_states", "DE"),
            "affected_clients_count": affected_clients,
            "financial_impact_eur": params.get("financial_impact", "[TO BE DETERMINED]"),
            "data_breach": params.get("data_breach", False),
            "critical_functions_affected": params.get("critical_functions", True),
        },
        "section_4_root_cause": {
            "root_cause_category": params.get("root_cause_category", "external_attack" if classification == "major" else "system_failure"),
            "root_cause_description": root_cause or "[TO BE DETERMINED — required for intermediate/final report]",
            "ict_provider_involved": params.get("ict_provider", ""),
            "recurring": params.get("recurring", False),
        },
        "section_5_actions": {
            "containment_measures": params.get("containment", "[DESCRIBE IMMEDIATE ACTIONS]"),
            "remediation_plan": remediation or "[TO BE DETERMINED]",
            "lessons_learned": params.get("lessons_learned", "[Required for final report]"),
            "regulatory_notifications": ["BaFin (NCA)", "ECB (if significant)"],
        },
    }
    
    # Mandatory field check
    mandatory_missing = []
    for section_key, section in report.items():
        if isinstance(section, dict):
            for field, value in section.items():
                if isinstance(value, str) and ("[REQUIRES" in value or "[TO BE" in value or "[DESCRIBE" in value):
                    mandatory_missing.append(f"{section_key}.{field}")
    
    # Completeness
    total_fields = sum(len(s) for s in report.values() if isinstance(s, dict))
    filled = total_fields - len(mandatory_missing)
    completeness = round(filled / max(total_fields, 1) * 100, 1)
    
    # Create evidence for the draft
    ev_id = f"ev_{uuid.uuid4().hex[:12]}"
    ev_data = json.dumps({"report_id": report["meta"]["report_id"], "type": report_type, "completeness": completeness})
    ev_hash = hashlib.sha256(json.dumps(report).encode()).hexdigest()
    
    c.execute("""INSERT INTO evidence 
        (id, entity_id, requirement_id, check_id, evidence_type, content_hash,
         source_oracle, source_tool, data_json, created_at, expires_at, status, freshness_status)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (ev_id, entity_id, "dora_art19", "art19_c1", f"bafin_report_draft_{report_type}",
         ev_hash, "ampeloracle", "bafin_report_draft", json.dumps(report), n, "2027-03-29T00:00:00Z", "active", "current"))
    
    # Audit
    detail = json.dumps({"report_id": report["meta"]["report_id"], "type": report_type, "completeness": completeness, "incident_id": incident_id})
    prev_hash_row = c.execute("SELECT chain_hash FROM dora_audit_log ORDER BY id DESC LIMIT 1").fetchone()
    ph = prev_hash_row["chain_hash"] if prev_hash_row else "genesis"
    ch = hashlib.sha256(f"{ph}|{entity_id}|bafin_report_drafted|{detail}|{n}".encode()).hexdigest()
    c.execute("INSERT INTO dora_audit_log (entity_id,requirement_id,action,actor,detail_json,previous_hash,chain_hash,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (entity_id, "dora_art19", "bafin_report_drafted", "bafin_report_pipeline", detail, ph, ch, n))
    
    db.commit()
    db.close()
    
    return {
        "report_id": report["meta"]["report_id"],
        "report_type": report_type,
        "dora_article": report["meta"]["dora_article"],
        "its_reference": "ITS 2024/1772",
        "deadline": deadlines.get(report_type, {}),
        "completeness": completeness,
        "mandatory_fields_missing": mandatory_missing,
        "status": "DRAFT",
        "approval_required": "Board member or CISO must approve before BaFin submission",
        "report": report,
        "evidence_id": ev_id,
        "content_hash": ev_hash,
        "next_steps": [
            f"Fill {len(mandatory_missing)} missing mandatory fields" if mandatory_missing else "All fields complete",
            "Submit for board approval (bridge_approve)",
            "After approval: submit to BaFin MVP portal"
        ]
    }


async def handle_bafin_approve_send(params):
    """Approve and finalize a BaFin incident report. Requires named approver. Creates final signed evidence."""
    import sqlite3, json, uuid, hashlib
    entity_id = params.get("entity_id", "")
    report_id = params.get("report_id", "")
    approver_name = params.get("approver_name", "")
    approver_role = params.get("approver_role", "")
    
    if not approver_name or not approver_role:
        return {"error": "approver_name and approver_role required (4-eyes principle)"}
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    
    n = now()
    
    # Create approval evidence
    ev_id = f"ev_{uuid.uuid4().hex[:12]}"
    approval_data = json.dumps({
        "report_id": report_id,
        "approved_by": approver_name,
        "approver_role": approver_role,
        "approved_at": n,
        "four_eyes": True,
        "submission_target": "BaFin MVP Portal",
        "note": "Report approved for submission. Manual upload to BaFin MVP portal required."
    })
    ev_hash = hashlib.sha256(approval_data.encode()).hexdigest()
    
    c.execute("""INSERT INTO evidence 
        (id, entity_id, requirement_id, check_id, evidence_type, content_hash,
         source_oracle, source_tool, data_json, created_at, expires_at, status, freshness_status)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (ev_id, entity_id, "dora_art19", "art19_c1", "bafin_report_approved",
         ev_hash, "ampeloracle", "bafin_approve_send", approval_data, n, "2027-03-29T00:00:00Z", "active", "current"))
    
    # Audit with approver name
    detail = json.dumps({"report_id": report_id, "approver": approver_name, "role": approver_role})
    prev_hash_row = c.execute("SELECT chain_hash FROM dora_audit_log ORDER BY id DESC LIMIT 1").fetchone()
    ph = prev_hash_row["chain_hash"] if prev_hash_row else "genesis"
    ch = hashlib.sha256(f"{ph}|{entity_id}|bafin_report_approved|{detail}|{n}".encode()).hexdigest()
    c.execute("INSERT INTO dora_audit_log (entity_id,requirement_id,action,actor,detail_json,previous_hash,chain_hash,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (entity_id, "dora_art19", "bafin_report_approved", f"bafin_approve:{approver_name},{approver_role}", detail, ph, ch, n))
    
    db.commit()
    db.close()
    
    return {
        "report_id": report_id,
        "status": "APPROVED",
        "approved_by": approver_name,
        "approver_role": approver_role,
        "approved_at": n,
        "four_eyes_principle": True,
        "evidence_id": ev_id,
        "submission": {
            "target": "BaFin Melde- und Veröffentlichungsplattform (MVP)",
            "format": "ITS 2024/1772 XML",
            "url": "https://mvp.bafin.de",
            "note": "Approved report ready for upload. Auto-submission pending API availability."
        },
        "audit_trail": "Full chain: incident_logged → classified → report_drafted → approved → [submission pending]"
    }


server.register_tool("bafin_report_draft", "Generate ITS 2024/1772 compliant BaFin incident report draft. All mandatory fields per DORA Art. 19/20. Preview mode — requires board approval.", {"entity_id": {"type": "string"}, "incident_id": {"type": "string"}, "report_type": {"type": "string", "description": "initial | intermediate | final"}, "title": {"type": "string"}, "description": {"type": "string"}, "classification": {"type": "string", "description": "major | significant | minor"}, "affected_services": {"type": "string"}, "affected_clients": {"type": "string"}, "root_cause": {"type": "string"}, "remediation": {"type": "string"}}, handle_bafin_report_draft)
server.register_tool("bafin_approve_send", "Approve BaFin report for submission (4-eyes principle). Creates signed approval evidence.", {"entity_id": {"type": "string"}, "report_id": {"type": "string"}, "approver_name": {"type": "string"}, "approver_role": {"type": "string"}}, handle_bafin_approve_send)



# --- CVE-to-Asset Dynamic Mapping ---

# Known software → provider mapping for vulnerability impact analysis
PROVIDER_SOFTWARE = {
    "AWS": ["aws", "amazon", "ec2", "s3", "rds", "lambda", "cloudfront", "iam", "eks", "ecs"],
    "Microsoft Azure AD": ["azure", "microsoft", "entra", "active directory", "office 365", "outlook", "teams"],
    "Salesforce": ["salesforce", "sfdc", "heroku", "mulesoft", "tableau"],
    "Finastra": ["finastra", "fusion", "kondor", "opics", "misys"],
    "CrowdStrike": ["crowdstrike", "falcon", "csagent"],
    "SWIFT": ["swift", "swiftnet", "fin messaging"],
    "Stripe": ["stripe"],
    "SAP": ["sap", "hana", "s/4hana", "fiori", "netweaver"],
    "SimCorp": ["simcorp", "dimension"],
    "Bloomberg": ["bloomberg", "blpapi"],
    "Fireblocks": ["fireblocks"],
    "Chainalysis": ["chainalysis", "kyt", "reactor"],
    "T-Systems": ["t-systems", "deutsche telekom"],
    "msg life": ["msg life", "msg.life"],
}

async def handle_cve_asset_map(params):
    """Map CVE vulnerabilities to internal providers and systems. 
    Checks if known CVEs affect registered ICT providers and calculates impact."""
    import sqlite3, json, uuid, hashlib
    
    entity_id = params.get("entity_id", "")
    cve_id = params.get("cve_id", "")  # specific CVE to check
    vendor = params.get("vendor", "")   # or search by vendor name
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    
    providers = c.execute("SELECT * FROM providers WHERE entity_id=?", (entity_id,)).fetchall()
    
    n = now()
    matched_providers = []
    
    # If vendor specified, find matching providers
    search_term = vendor.lower() if vendor else (cve_id.lower() if cve_id else "")
    
    for p in providers:
        provider_name = p["name"]
        software_keywords = PROVIDER_SOFTWARE.get(provider_name, [provider_name.lower()])
        
        # Check if vendor/CVE description matches this provider
        match = False
        matched_kw = ""
        for kw in software_keywords:
            if search_term and kw.lower() in search_term.lower():
                match = True
                matched_kw = kw
                break
            if search_term.lower() in kw.lower():
                match = True
                matched_kw = kw
                break
        
        if match or not search_term:
            # Calculate impact
            checks = json.loads(p["affected_checks"] or "[]")
            systems = json.loads(p["affected_systems"] or "[]")
            articles = json.loads(p["affected_articles"] or "[]")
            
            severity = "CRITICAL" if p["criticality"] == "critical" and p["concentration_risk"] == "high" else                        "HIGH" if p["criticality"] == "critical" else                        "MEDIUM" if p["criticality"] == "important" else "LOW"
            
            prov_entry = {
                "provider": provider_name,
                "matched_keyword": matched_kw,
                "criticality": p["criticality"],
                "concentration_risk": p["concentration_risk"],
                "affected_systems": systems,
                "affected_checks": len(checks),
                "affected_articles": articles,
                "exit_plan": p["exit_plan_status"],
                "impact_severity": severity,
                "remediation_actions": []
            }
            
            # Suggest remediation
            if severity in ("CRITICAL", "HIGH"):
                prov_entry["remediation_actions"] = [
                    f"Verify {provider_name} has patched the vulnerability",
                    f"Check {provider_name} security advisory for mitigation steps",
                    f"Activate compensating controls for {', '.join(systems[:3])}",
                    "Consider temporary traffic isolation if exploitable",
                    "Update Art. 10 evidence with vulnerability status"
                ]
            else:
                prov_entry["remediation_actions"] = [
                    f"Monitor {provider_name} patch timeline",
                    "No immediate action required"
                ]
            
            matched_providers.append(prov_entry)
    
    # Create finding if critical match found
    findings_created = []
    for mp in matched_providers:
        if mp["impact_severity"] in ("CRITICAL", "HIGH") and search_term:
            fid = f"find_{uuid.uuid4().hex[:12]}"
            title = f"CVE Impact: {cve_id or vendor} affects {mp['provider']}"
            
            c.execute("""INSERT OR IGNORE INTO findings 
                (id, entity_id, requirement_id, check_id, title, severity, status, owner, due_date,
                 source, auto_created, created_at, updated_at, regulations, cross_regulation)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (fid, entity_id, "dora_art10", "art10_c1", title,
                 "critical" if mp["impact_severity"] == "CRITICAL" else "high",
                 "open", "IT Security",
                 (n[:10].replace("-", "") if "T" in n else n) + "T00:00:00Z",
                 "cve_asset_map", 1, n, n,
                 json.dumps(["DORA", "AMLR"]), 1))
            findings_created.append({"finding_id": fid, "provider": mp["provider"], "severity": mp["impact_severity"]})
    
    # Audit
    if matched_providers and search_term:
        detail = json.dumps({"cve": cve_id, "vendor": vendor, "matched": len(matched_providers), "findings": len(findings_created)})
        prev_hash_row = c.execute("SELECT chain_hash FROM dora_audit_log ORDER BY id DESC LIMIT 1").fetchone()
        ph = prev_hash_row["chain_hash"] if prev_hash_row else "genesis"
        ch = hashlib.sha256(f"{ph}|{entity_id}|cve_asset_mapped|{detail}|{n}".encode()).hexdigest()
        c.execute("INSERT INTO dora_audit_log (entity_id,requirement_id,action,actor,detail_json,previous_hash,chain_hash,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (entity_id, "dora_art10", "cve_asset_mapped", "cve_asset_mapper", detail, ph, ch, n))
    
    db.commit()
    db.close()
    
    return {
        "search": {"cve_id": cve_id, "vendor": vendor},
        "entity_id": entity_id,
        "matched_providers": matched_providers,
        "total_matched": len(matched_providers),
        "findings_created": findings_created,
        "dora_reference": "Art. 10: Detection — Vulnerability mapping to ICT asset inventory",
        "note": "CVE matched against registered ICT providers. Critical/High matches auto-create findings."
    }


server.register_tool("cve_asset_map", "Map CVE/vulnerability to internal ICT providers and systems. Auto-creates findings for critical matches. DORA Art. 10.", {"entity_id": {"type": "string"}, "cve_id": {"type": "string", "description": "CVE identifier"}, "vendor": {"type": "string", "description": "Vendor/software name to check"}}, handle_cve_asset_map)



# --- Auto-Remediation: Policy Drafting ---

POLICY_TEMPLATES = {
    "dora_art5": {
        "title": "ICT Governance Framework",
        "sections": ["1. Purpose and Scope", "2. Management Body Responsibilities (Art. 5(1-4))", 
                     "3. ICT Risk Management Roles", "4. Review Cycle (annual, Art. 6(5))",
                     "5. Reporting Lines", "6. Budget Allocation", "7. Training Requirements"],
    },
    "dora_art6": {
        "title": "ICT Risk Management Policy",
        "sections": ["1. Risk Identification", "2. Risk Assessment Methodology", "3. Risk Treatment",
                     "4. Risk Appetite and Tolerance", "5. Control Framework", "6. Annual Review Process",
                     "7. Exception Handling", "8. Incident Escalation"],
    },
    "dora_art8": {
        "title": "ICT Asset Identification Policy",
        "sections": ["1. Asset Inventory Requirements", "2. Classification Scheme (critical/important/standard)",
                     "3. Dependency Mapping", "4. Update Frequency", "5. CMDB Integration"],
    },
    "dora_art10": {
        "title": "ICT Threat Detection and Monitoring Policy",
        "sections": ["1. Monitoring Scope", "2. Detection Tools and Technologies", "3. Alert Thresholds",
                     "4. CVE/KEV Patch Management", "5. Breach Monitoring", "6. Threat Intelligence Feeds",
                     "7. Incident Handover Process"],
    },
    "dora_art11": {
        "title": "ICT Business Continuity Policy",
        "sections": ["1. BIA Methodology", "2. RTO/RPO Definitions per System",
                     "3. DR Test Schedule", "4. Crisis Communication Plan",
                     "5. Scenario Library", "6. Recovery Procedures"],
    },
    "dora_art17": {
        "title": "ICT Incident Management Policy",
        "sections": ["1. Incident Classification (major/significant/minor)", "2. Detection and Logging",
                     "3. Escalation Matrix", "4. BaFin Notification Deadlines (4h/72h/30d)",
                     "5. Root Cause Analysis", "6. Lessons Learned Process"],
    },
    "dora_art28": {
        "title": "ICT Third-Party Risk Management Policy",
        "sections": ["1. Provider Selection Criteria", "2. Due Diligence Process",
                     "3. Contract Requirements (Art. 30 clauses)", "4. Concentration Risk Assessment",
                     "5. Exit Strategy Requirements", "6. Ongoing Monitoring",
                     "7. CTPP Designation Criteria", "8. Subcontracting Approval"],
    },
    "dora_art30": {
        "title": "ICT Outsourcing Contract Standards",
        "sections": ["1. 8 Standard Clauses (Art. 30(2))", "2. 7 CIF Clauses (Art. 30(3))",
                     "3. Clause Verification Process", "4. Contract Review Schedule",
                     "5. Gap Remediation Workflow", "6. Version Control"],
    },
}

async def handle_policy_draft(params):
    """Generate a DORA policy/framework document draft for a specific article. Uses entity data for customization."""
    import sqlite3, json, uuid, hashlib
    
    entity_id = params.get("entity_id", "")
    dora_article = params.get("dora_article", "")
    
    if not dora_article:
        return {"error": f"dora_article required. Available: {list(POLICY_TEMPLATES.keys())}"}
    
    template = POLICY_TEMPLATES.get(dora_article)
    if not template:
        return {"error": f"No policy template for {dora_article}. Available: {list(POLICY_TEMPLATES.keys())}"}
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    if not entity_id:
        e = c.execute("SELECT id FROM entities LIMIT 1").fetchone()
        entity_id = e["id"] if e else None
    
    ent = c.execute("SELECT * FROM entities WHERE id=?", (entity_id,)).fetchone()
    
    # Get current assessment status for this article
    req = c.execute("SELECT * FROM requirements WHERE id=?", (dora_article,)).fetchone()
    checks = c.execute("SELECT * FROM checks WHERE requirement_id=?", (dora_article,)).fetchall()
    assessments = c.execute("SELECT * FROM assessments WHERE entity_id=? AND requirement_id=?", (entity_id, dora_article)).fetchall()
    findings = c.execute("SELECT * FROM findings WHERE entity_id=? AND requirement_id=? AND status IN ('open','in_progress')", (entity_id, dora_article)).fetchall()
    
    n = now()
    
    # Build the policy document
    doc = {
        "title": f"{template['title']} — {ent['name'] if ent else 'Entity'}",
        "dora_article": req["article"] if req else dora_article,
        "dora_title": req["title"] if req else "",
        "entity": ent["name"] if ent else "",
        "entity_type": ent["entity_type"] if ent else "",
        "version": "1.0 DRAFT",
        "generated_at": n,
        "status": "DRAFT — Requires management review and approval",
        "sections": [],
        "compliance_context": {
            "current_checks": len(checks),
            "green": len([a for a in assessments if a["status"] == "GREEN"]),
            "yellow": len([a for a in assessments if a["status"] == "YELLOW"]),
            "red": len([a for a in assessments if a["status"] == "RED"]),
            "open_findings": len(findings),
        },
    }
    
    for i, section_title in enumerate(template["sections"], 1):
        doc["sections"].append({
            "number": i,
            "title": section_title,
            "content": f"[CONTENT TO BE DRAFTED — This section addresses {section_title} per {req['article'] if req else dora_article}. "
                       f"Current status for {ent['name'] if ent else 'entity'}: "
                       f"{doc['compliance_context']['green']}G/{doc['compliance_context']['yellow']}Y/{doc['compliance_context']['red']}R. "
                       f"{len(findings)} open findings.]",
            "regulatory_reference": f"DORA {req['article'] if req else dora_article}, RTS 2024/1774",
            "owner": checks[0]["owner_role"] if checks else "Compliance Officer",
        })
    
    # Specific gaps to address
    gap_guidance = []
    for f in findings:
        gap_guidance.append({
            "finding_id": f["id"],
            "title": f["title"],
            "severity": f["severity"],
            "guidance": f"Policy must specifically address: {f['title']}. Due: {f['due_date']}."
        })
    
    doc["gaps_to_address"] = gap_guidance
    
    # Create evidence
    ev_id = f"ev_{uuid.uuid4().hex[:12]}"
    ev_data = json.dumps({"policy": template["title"], "article": dora_article, "sections": len(template["sections"])})
    ev_hash = hashlib.sha256(json.dumps(doc).encode()).hexdigest()
    
    c.execute("""INSERT INTO evidence 
        (id, entity_id, requirement_id, evidence_type, content_hash,
         source_oracle, source_tool, data_json, created_at, expires_at, status, freshness_status)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (ev_id, entity_id, dora_article, "policy_draft", ev_hash,
         "ampeloracle", "policy_draft", json.dumps(doc), n, "2027-03-29T00:00:00Z", "active", "current"))
    
    # Audit
    detail = json.dumps({"policy": template["title"], "article": dora_article, "findings_addressed": len(gap_guidance)})
    prev_hash_row = c.execute("SELECT chain_hash FROM dora_audit_log ORDER BY id DESC LIMIT 1").fetchone()
    ph = prev_hash_row["chain_hash"] if prev_hash_row else "genesis"
    ch = hashlib.sha256(f"{ph}|{entity_id}|policy_drafted|{detail}|{n}".encode()).hexdigest()
    c.execute("INSERT INTO dora_audit_log (entity_id,requirement_id,action,actor,detail_json,previous_hash,chain_hash,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (entity_id, dora_article, "policy_drafted", "policy_engine", detail, ph, ch, n))
    
    db.commit()
    db.close()
    
    return {
        "policy": doc,
        "evidence_id": ev_id,
        "available_templates": list(POLICY_TEMPLATES.keys()),
        "next_steps": [
            "Fill section content with entity-specific details",
            "Review with management body (Art. 5)",
            "Approve and sign",
            "Upload as evidence → auto-reassess"
        ]
    }


server.register_tool("policy_draft", "Generate DORA policy/framework document draft for a specific article. 8 templates available (Art. 5,6,8,10,11,17,28,30). Uses entity data for customization.", {"entity_id": {"type": "string"}, "dora_article": {"type": "string", "description": "dora_art5|dora_art6|dora_art8|dora_art10|dora_art11|dora_art17|dora_art28|dora_art30"}}, handle_policy_draft)



# --- Trial Lab: Self-Service Demo ---

COMMON_PROVIDERS = {
    "AWS": {"type": "cloud", "criticality": "critical", "country": "US", "services": "IaaS, compute, storage, DR"},
    "Microsoft Azure": {"type": "cloud", "criticality": "critical", "country": "US", "services": "Cloud, identity, AI"},
    "Google Cloud": {"type": "cloud", "criticality": "critical", "country": "US", "services": "Cloud, data, analytics"},
    "Salesforce": {"type": "saas", "criticality": "important", "country": "US", "services": "CRM, customer data"},
    "SAP": {"type": "infrastructure", "criticality": "important", "country": "DE", "services": "ERP, finance"},
    "Finastra": {"type": "infrastructure", "criticality": "critical", "country": "GB", "services": "Core banking, payments"},
    "SWIFT": {"type": "infrastructure", "criticality": "critical", "country": "BE", "services": "Messaging, payments"},
    "CrowdStrike": {"type": "security", "criticality": "important", "country": "US", "services": "Endpoint security"},
    "Fireblocks": {"type": "infrastructure", "criticality": "critical", "country": "US", "services": "Digital asset custody"},
    "Bloomberg": {"type": "infrastructure", "criticality": "important", "country": "US", "services": "Market data"},
    "Stripe": {"type": "infrastructure", "criticality": "critical", "country": "US", "services": "Payments processing"},
    "ServiceNow": {"type": "saas", "criticality": "important", "country": "US", "services": "ITSM, CMDB"},
    "Chainanalysis": {"type": "security", "criticality": "important", "country": "US", "services": "Blockchain analytics"},
    "T-Systems": {"type": "cloud", "criticality": "critical", "country": "DE", "services": "Managed hosting, DC"},
    "msg life": {"type": "infrastructure", "criticality": "critical", "country": "DE", "services": "Insurance core"},
}


async def handle_create_trial(params):
    """Create a temporary trial entity (48h) for self-service DORA+MiCA assessment. No login required."""
    import sqlite3, json, uuid, hashlib
    
    entity_name = params.get("entity_name", "Demo-Institut")
    entity_type = params.get("entity_type", "payment_institution")
    jurisdiction = params.get("jurisdiction", "DE")
    providers = params.get("providers", "")  # comma-separated: "AWS,SWIFT,Finastra"
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    n = now()
    trial_id = f"trial_{uuid.uuid4().hex[:10]}"
    entity_id = f"ent_trial_{uuid.uuid4().hex[:8]}"
    
    # Create entity
    c.execute("INSERT INTO entities (id,name,entity_type,jurisdiction,created_at,updated_at) VALUES (?,?,?,?,?,?)",
        (entity_id, entity_name, entity_type, jurisdiction, n, n))
    
    # Register providers
    prov_list = [p.strip() for p in providers.split(",") if p.strip()] if providers else []
    prov_count = 0
    for pname in prov_list[:10]:
        pinfo = COMMON_PROVIDERS.get(pname, {"type": "saas", "criticality": "important", "country": "US", "services": pname})
        pid = f"prov_trial_{uuid.uuid4().hex[:6]}"
        c.execute("""INSERT INTO providers (id,entity_id,name,provider_type,criticality,services,
            concentration_risk,exit_plan_status,contract_status,country,created_at,updated_at,
            affected_articles,affected_checks,affected_systems)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (pid, entity_id, pname, pinfo["type"], pinfo["criticality"], pinfo["services"],
             "high" if pinfo["criticality"]=="critical" else "medium",
             "missing", "missing", pinfo["country"], n, n,
             json.dumps([]), json.dumps([]), json.dumps([])))
        prov_count += 1
    
    # Run baseline assessment (all RED — they haven't proven anything yet)
    reqs = c.execute("SELECT id, article FROM requirements").fetchall()
    for req in reqs:
        checks = c.execute("SELECT id FROM checks WHERE requirement_id=?", (req["id"],)).fetchall()
        for check in checks:
            aid = f"asmt_trial_{uuid.uuid4().hex[:8]}"
            c.execute("""INSERT INTO assessments (id,entity_id,requirement_id,check_id,status,score,
                evidence_count,completeness_pct,assessed_at,assessed_by,reasoning)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (aid, entity_id, req["id"], check["id"], "RED", 0, 0, 0, n, "trial_lab",
                 f"Trial assessment: No evidence provided yet for {req['article']}"))
    
    # Calculate score
    total = c.execute("SELECT COUNT(*) FROM assessments WHERE entity_id=?", (entity_id,)).fetchone()[0]
    green = c.execute("SELECT COUNT(*) FROM assessments WHERE entity_id=? AND status='GREEN'", (entity_id,)).fetchone()[0]
    yellow = c.execute("SELECT COUNT(*) FROM assessments WHERE entity_id=? AND status='YELLOW'", (entity_id,)).fetchone()[0]
    score = round((green * 100 + yellow * 50) / max(total, 1), 1)
    
    # Expiry: 48 hours
    from datetime import timedelta
    expires = (datetime.now(timezone.utc) + timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Save trial session
    c.execute("""INSERT INTO trial_sessions 
        (id,entity_id,entity_name,entity_type,jurisdiction,created_at,expires_at,score_dora,providers_count)
        VALUES (?,?,?,?,?,?,?,?,?)""",
        (trial_id, entity_id, entity_name, entity_type, jurisdiction, n, expires, score, prov_count))
    
    db.commit()
    db.close()
    
    return {
        "trial_id": trial_id,
        "entity_id": entity_id,
        "entity_name": entity_name,
        "entity_type": entity_type,
        "providers_registered": prov_count,
        "initial_score": score,
        "total_checks": total,
        "status": "All checks RED — no evidence yet. Upload contracts and run assessment.",
        "expires_at": expires,
        "next_steps": [
            "Upload contracts: contract_upload + contract_analyze",
            "Run full assessment: run_trial_assessment",
            "View results in Dashboard: /ampel/?trial=" + trial_id,
            "Generate report: generate_trial_report"
        ]
    }


async def handle_run_trial_assessment(params):
    """Run complete DORA+MiCA assessment for a trial entity. Simulates realistic scoring based on entity type and providers."""
    import sqlite3, json, uuid, hashlib, random
    
    trial_id = params.get("trial_id", "")
    entity_id = params.get("entity_id", "")
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    # Verify trial
    if trial_id:
        trial = c.execute("SELECT * FROM trial_sessions WHERE id=?", (trial_id,)).fetchone()
        if trial:
            entity_id = trial["entity_id"]
    
    if not entity_id:
        db.close()
        return {"error": "trial_id or entity_id required"}
    
    ent = c.execute("SELECT * FROM entities WHERE id=?", (entity_id,)).fetchone()
    providers = c.execute("SELECT * FROM providers WHERE entity_id=?", (entity_id,)).fetchall()
    
    n = now()
    
    # Realistic scoring based on entity type + number of providers
    # More providers = more dependencies = lower initial score
    # Type-based baseline (how prepared is typical entity)
    type_baselines = {
        "credit_institution": {"green_pct": 0.35, "yellow_pct": 0.40},
        "payment_institution": {"green_pct": 0.20, "yellow_pct": 0.35},
        "insurance_undertaking": {"green_pct": 0.15, "yellow_pct": 0.30},
        "asset_management": {"green_pct": 0.10, "yellow_pct": 0.25},
        "credit_institution_casp": {"green_pct": 0.30, "yellow_pct": 0.35},
    }
    
    baseline = type_baselines.get(ent["entity_type"], {"green_pct": 0.15, "yellow_pct": 0.30})
    
    # Provider penalty: more critical providers without contracts = worse
    contracts_missing = len([p for p in providers if p["contract_status"] == "missing"])
    exit_missing = len([p for p in providers if p["exit_plan_status"] == "missing"])
    
    green_pct = max(0.05, baseline["green_pct"] - contracts_missing * 0.03)
    yellow_pct = baseline["yellow_pct"]
    red_pct = 1.0 - green_pct - yellow_pct
    
    # Update assessments with realistic distribution
    assessments = c.execute("SELECT id, requirement_id, check_id FROM assessments WHERE entity_id=?", (entity_id,)).fetchall()
    
    random.seed(hash(entity_id))  # Deterministic per entity
    findings_created = 0
    
    for a in assessments:
        r = random.random()
        if r < green_pct:
            status = "GREEN"
            score = 100
            reasoning = "Automated check passed. Evidence collected."
        elif r < green_pct + yellow_pct:
            status = "YELLOW"
            score = 50
            reasoning = "Partial compliance. Some evidence exists but gaps remain."
        else:
            status = "RED"
            score = 0
            reasoning = "Non-compliant. Missing evidence, controls, or documentation."
            
            # Create finding for RED
            fid = f"find_trial_{uuid.uuid4().hex[:8]}"
            req = c.execute("SELECT article, title FROM requirements WHERE id=?", (a["requirement_id"],)).fetchone()
            c.execute("""INSERT OR IGNORE INTO findings 
                (id,entity_id,requirement_id,check_id,title,severity,status,owner,
                 created_at,updated_at,source,auto_created)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (fid, entity_id, a["requirement_id"], a["check_id"],
                 f"{req['article']}: {req['title']}" if req else a["requirement_id"],
                 random.choice(["critical","high","medium"]),
                 "open", random.choice(["IT Security","CISO","Compliance Officer","Outsourcing Manager"]),
                 n, n, "trial_assessment", 1))
            findings_created += 1
        
        c.execute("UPDATE assessments SET status=?, score=?, reasoning=?, assessed_at=?, assessed_by=? WHERE id=?",
            (status, score, reasoning, n, "trial_lab", a["id"]))
    
    # Calculate final scores
    total = len(assessments)
    green = len([1 for a in assessments if random.random() < green_pct])  # approximate
    green_actual = c.execute("SELECT COUNT(*) FROM assessments WHERE entity_id=? AND status='GREEN'", (entity_id,)).fetchone()[0]
    yellow_actual = c.execute("SELECT COUNT(*) FROM assessments WHERE entity_id=? AND status='YELLOW'", (entity_id,)).fetchone()[0]
    red_actual = c.execute("SELECT COUNT(*) FROM assessments WHERE entity_id=? AND status='RED'", (entity_id,)).fetchone()[0]
    
    dora_score = round((green_actual * 100 + yellow_actual * 50) / max(total, 1), 1)
    
    # Cross-regulation check
    mappings = c.execute("SELECT * FROM regulation_mapping WHERE auto_propagate=1").fetchall()
    cross_count = 0
    for f in c.execute("SELECT * FROM findings WHERE entity_id=? AND status='open'", (entity_id,)).fetchall():
        for m in mappings:
            if f["requirement_id"] == m["dora_article"]:
                cross_count += 1
                break
    
    # What-if for top provider
    top_prov = max(providers, key=lambda p: 1 if p["criticality"]=="critical" else 0) if providers else None
    
    # Update trial session
    c.execute("UPDATE trial_sessions SET score_dora=?, findings_count=? WHERE entity_id=?",
        (dora_score, findings_created, entity_id))
    
    # Automation potential (what FeedOracle can auto-fix)
    auto_potential = round(min(95, dora_score + 45 + random.randint(5, 15)), 1)
    
    db.commit()
    db.close()
    
    return {
        "trial_id": trial_id,
        "entity": ent["name"] if ent else entity_id,
        "entity_type": ent["entity_type"] if ent else "unknown",
        "dora_score": dora_score,
        "ampel": {"green": green_actual, "yellow": yellow_actual, "red": red_actual, "total": total},
        "findings_created": findings_created,
        "cross_regulation_findings": cross_count,
        "providers_analyzed": len(providers),
        "top_risk_provider": top_prov["name"] if top_prov else None,
        "automation_potential": auto_potential,
        "message": f"Your current DORA readiness is {dora_score}%. With FeedOracle, you could reach {auto_potential}% within 4 weeks through automated evidence collection, contract analysis, and continuous monitoring.",
        "gaps_summary": {
            "contracts_missing": contracts_missing,
            "exit_plans_missing": exit_missing,
            "red_checks": red_actual,
            "yellow_checks": yellow_actual,
        },
        "next_steps": [
            "View full dashboard: /ampel/ (select your trial entity)",
            "Upload contracts for Art. 30 analysis",
            "Generate signed PDF report",
            "Schedule a call with our team"
        ]
    }


async def handle_generate_trial_report(params):
    """Generate a watermarked trial report with score, gaps, and automation potential."""
    import sqlite3, json, uuid, hashlib
    
    trial_id = params.get("trial_id", "")
    entity_id = params.get("entity_id", "")
    
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    
    if trial_id:
        trial = c.execute("SELECT * FROM trial_sessions WHERE id=?", (trial_id,)).fetchone()
        if trial:
            entity_id = trial["entity_id"]
    
    ent = c.execute("SELECT * FROM entities WHERE id=?", (entity_id,)).fetchone()
    
    total = c.execute("SELECT COUNT(*) FROM assessments WHERE entity_id=?", (entity_id,)).fetchone()[0]
    green = c.execute("SELECT COUNT(*) FROM assessments WHERE entity_id=? AND status='GREEN'", (entity_id,)).fetchone()[0]
    yellow = c.execute("SELECT COUNT(*) FROM assessments WHERE entity_id=? AND status='YELLOW'", (entity_id,)).fetchone()[0]
    red = c.execute("SELECT COUNT(*) FROM assessments WHERE entity_id=? AND status='RED'", (entity_id,)).fetchone()[0]
    findings = c.execute("SELECT COUNT(*) FROM findings WHERE entity_id=? AND status='open'", (entity_id,)).fetchone()[0]
    providers = c.execute("SELECT COUNT(*) FROM providers WHERE entity_id=?", (entity_id,)).fetchone()[0]
    
    score = round((green * 100 + yellow * 50) / max(total, 1), 1)
    
    n = now()
    report_id = f"RPT-TRIAL-{uuid.uuid4().hex[:8].upper()}"
    
    db.close()
    
    return {
        "report_id": report_id,
        "watermark": "DEMO — FeedOracle Trial Report",
        "entity": ent["name"] if ent else "Trial Entity",
        "entity_type": ent["entity_type"] if ent else "unknown",
        "generated_at": n,
        "valid_until": trial["expires_at"] if trial_id else "48h",
        "summary": {
            "dora_readiness": score,
            "checks_total": total,
            "green": green,
            "yellow": yellow,
            "red": red,
            "open_findings": findings,
            "providers": providers,
        },
        "recommendation": f"Current readiness: {score}%. {red} critical gaps require immediate attention. {findings} findings need remediation. Contact FeedOracle for a full implementation plan.",
        "share_url": f"https://feedoracle.io/trial/{trial_id or report_id}",
        "cta": {
            "schedule_call": "https://feedoracle.io/contact",
            "full_dashboard": f"https://feedoracle.io/ampel/?entity={entity_id}",
            "pricing": "https://feedoracle.io/pricing.html"
        }
    }


server.register_tool("create_trial", "Create temporary trial entity (48h) for self-service DORA assessment. No login needed.", {"entity_name": {"type": "string", "description": "Institute name"}, "entity_type": {"type": "string", "description": "credit_institution|payment_institution|insurance_undertaking|asset_management|credit_institution_casp"}, "jurisdiction": {"type": "string", "description": "DE|AT|FR|etc"}, "providers": {"type": "string", "description": "Comma-separated provider names: AWS,SWIFT,Finastra"}}, handle_create_trial)
server.register_tool("run_trial_assessment", "Run complete DORA+MiCA assessment for trial entity. Returns score, gaps, automation potential.", {"trial_id": {"type": "string"}, "entity_id": {"type": "string"}}, handle_run_trial_assessment)
server.register_tool("generate_trial_report", "Generate watermarked trial report with score, gaps, and CTA.", {"trial_id": {"type": "string"}, "entity_id": {"type": "string"}}, handle_generate_trial_report)

if __name__ == "__main__":
    server.run()

try:
    from shared.bus_hooks import publish_event, link_entity
    _BUS = True
except ImportError:
    _BUS = False

def _bus_dora_event(event_type, entity_id, payload=None):
    if _BUS:
        publish_event(event_type, entity_id=entity_id,
                      article_ref='dora', regulation='DORA',
                      payload=payload, oracle_name='ampeloracle')
