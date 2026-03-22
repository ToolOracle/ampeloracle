# 🚦 AmpelOracle

**DORA Compliance MCP Server** — 22 tools | Part of [ToolOracle](https://tooloracle.io)

![Tools](https://img.shields.io/badge/MCP_Tools-22-10B898?style=flat-square)
![Status](https://img.shields.io/badge/Status-Live-00C853?style=flat-square)
![Tier](https://img.shields.io/badge/Tier-Enterprise-FF6D00?style=flat-square)
![Bus](https://img.shields.io/badge/Oracle_Bus-Connected-00C853?style=flat-square)

## Quick Connect

```bash
# Claude Desktop / Cursor / Windsurf
npx -y mcp-remote https://tooloracle.io/ampel/mcp/
```

```json
// claude_desktop_config.json
{
  "mcpServers": {
    "ampeloracle": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://tooloracle.io/ampel/mcp/"]
    }
  }
}
```

## Tools (22)

| Tool | Description |
|------|-------------|
| `readiness_check` | Full DORA readiness score + Ampel per article. Returns GREEN/YELLOW/RED/GREY for |
| `article_status` | Detailed Ampel for a specific DORA article. Each check with GREEN/YELLOW/RED con |
| `gap_report` | DORA compliance gaps. RED/GREY/YELLOW items with priority and required actions. |
| `evidence_summary` | All evidence artefacts for an entity with hashes and expiry dates. |
| `collect_art10` | Collect live Art. 10 evidence from NVD, CISA KEV, CERT-Bund. Auto-assesses. |
| `entity_list` | List all registered regulated entities. |
| `create_entity` | Register a new regulated entity. |
| `audit_trail` | Chain-linked audit log with integrity check. |
| `generate_report` | Generate data-driven DORA Ampel PDF report. Score, gap analysis, provider regist |
| `freshness_check` | Run freshness watchdog. Expires stale evidence, downgrades GREEN->YELLOW->GREY i |
| `bridge_report` | Bridge gap analysis: classifies gaps by DATA/EVIDENCE/POLICY/WORKFLOW with closu |
| `register_provider` | Register an ICT third-party provider for DORA Art. 28 Register of Information. S |
| `check_contract` | Check DORA Art. 30 contract clauses for a provider. Returns PASS/WARN/BLOCK with |
| `assess_all` | Re-run full assessment for an entity. Recomputes Ampel statuses from all availab |
| `bridge_resolve` | Start bridge resolution workflow. Generates templates (Risk Acceptance, Contract |
| `bridge_approve` | Approve or reject a bridge resolution. On approval: creates signed evidence, upg |
| `bridge_status` | Check status of all bridge resolution workflows for an entity. Shows open, pendi |
| `reg_watchdog` | AI Regulatory Watchdog: scrapes EBA/ESMA/BaFin/CERT-Bund for DORA updates. Retur |
| `azure_ad_check` | Live Azure AD integration: MFA registration %, risky users, conditional access p |
| `servicenow_sync` | ServiceNow incident + change management sync. DORA Art. 17/21 evidence. Returns  |
| `llm_clause_check` | LLM-based DORA Art. 30 contract analysis. Paste contract text, get clause-by-cla |
| `bus_status` | Oracle Event Bus status: events, cross-refs, connected oracles. |

## Pricing

| Tier | Rate Limit | Price |
|------|-----------|-------|
| Free | 10 calls/day | €0 |
| Pro | 1,000 calls/day | €99/month |
| Enterprise | Unlimited | Custom |

> **Note:** This is a compliance oracle. Full tool access requires a Pro or Enterprise subscription. Free tier includes read-only assessment tools.

## Part of ToolOracle

AmpelOracle is one of **42 specialized MCP servers** in the [ToolOracle](https://tooloracle.io) ecosystem — the largest collection of production-ready MCP tools for AI agents.

### DORA Coverage

**Related Oracles:**
- [FeedOracle](https://feedoracle.io) — Evidence-grade compliance data infrastructure
- [ToolOracle](https://tooloracle.io) — 42 Oracles, 390+ MCP Tools

## Links

- 🌐 Live: `https://tooloracle.io/ampel/mcp/`
- 📚 Docs: [tooloracle.io/docs](https://tooloracle.io/docs)
- 🏠 Platform: [tooloracle.io](https://tooloracle.io)

---

*Built by [FeedOracle](https://feedoracle.io) — Evidence by Design*
