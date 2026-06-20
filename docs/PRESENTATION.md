# Identity Sprawl & Privileged Access Abuse Detection
## Hackathon Presentation Guide

---

## 1. Problem Statement (2 minutes)

### The Challenge
In hybrid enterprises, employees have identities scattered across **multiple platforms** — Active Directory, AWS IAM, Okta — each with different username formats, different admin groups, and different lifecycle management.

### Why This Matters for Societe Generale
- **5,000+ identities** spread across 3-6 platforms
- When someone leaves, their account might be disabled in AD but **remain active in AWS with admin access**
- Service accounts accumulate privileges over years with **no human owner**
- API tokens expire but **continue to be used** (credential compromise indicator)
- Traditional SIEM alerts generate thousands of standalone findings — **SOC teams drown in noise**

### Real-World Impact
- **2023 Uber breach**: Attacker used a dormant admin account
- **2022 Okta breach**: Compromised service account with excessive permissions
- **Capital One**: Over-privileged role exploited for data exfiltration

---

## 2. Our Solution (3 minutes)

### What We Built
A **full-stack identity risk detection platform** that:

1. **Consolidates** 272 identities across AD, AWS IAM, and Okta into a unified view
2. **Computes effective privileges** through nested group inheritance (NetworkX graph)
3. **Detects 8 risk categories** using deterministic, explainable rules
4. **Scores and clusters** 283 findings into 72 actionable incidents (74.6% alert reduction)
5. **Generates platform-specific remediation** commands (PowerShell, AWS CLI, Okta CLI)
6. **Maps to compliance frameworks** (NIST, CIS, GDPR, ISO 27001, SOX, MITRE ATT&CK)

### Key Differentiators
- **Graph-based privilege analysis** — not just flat permission lists, but transitive closure through group nesting
- **Cross-platform identity resolution** — same person, different usernames, unified risk view
- **Explainable detection** — every finding traces to specific evidence (no black-box ML)
- **False positive prevention** — justified access exceptions are excluded from alerting
- **74.6% alert consolidation** — SOC team sees 72 incidents instead of 283 raw findings

---

## 3. Architecture Overview (3 minutes)

### System Layers

```
┌─────────────────────────────────────────────────┐
│           Interactive Dashboard (vis.js)          │
│    Graph Viz │ Risk Table │ Identity Detail       │
├─────────────────────────────────────────────────┤
│           REST API (Flask, 10 endpoints)          │
├─────────────────────────────────────────────────┤
│    Detection Engine (8 Rules + Scoring)           │
│    ┌────────────┐ ┌──────────┐ ┌─────────────┐  │
│    │ Risk       │ │ Incident │ │ Remediation │  │
│    │ Detector   │ │ Cluster  │ │ Generator   │  │
│    └────────────┘ └──────────┘ └─────────────┘  │
├─────────────────────────────────────────────────┤
│    Identity Resolution + Privilege Graph          │
│    ┌────────────┐ ┌──────────────────────────┐   │
│    │ Fuzzy      │ │ NetworkX DiGraph          │   │
│    │ Matcher    │ │ (BFS effective perms)     │   │
│    └────────────┘ └──────────────────────────┘   │
├─────────────────────────────────────────────────┤
│    Synthetic Data Layer (250 people, 974 events)  │
└─────────────────────────────────────────────────┘
```

### Technology Choices & Rationale

| Choice | Why |
|--------|-----|
| **Flask** over FastAPI | Simpler template rendering, no async complexity for demo |
| **NetworkX** for graph | Pure Python, BFS/DFS built-in, transitive closure |
| **vis.js** for visualization | Interactive hierarchical layout, zero build tools |
| **Rules over ML** | Explainable, deterministic, auditable — critical for compliance |
| **Faker** for data | Realistic names, emails, IPs — convincing demo |

---

## 4. Detection Engine Deep-Dive (5 minutes)

### 8 Detection Rules

| # | Rule | What It Catches | MITRE Technique |
|---|------|-----------------|-----------------|
| 1 | **Orphaned Account** | Active accounts with no HR record | T1078 Valid Accounts |
| 2 | **Dormant Admin** | Admin accounts inactive 90+ days | T1078.001 Default Accounts |
| 3 | **Privilege Spike** | Sudden admin grant to non-admin user | T1098 Account Manipulation |
| 4 | **Cross-Platform Mismatch** | Disabled in AD but active in AWS | T1550 Alt Auth Material |
| 5 | **Offboarding Failure** | Terminated employee, account still active | T1078 Valid Accounts |
| 6 | **Excessive Permissions** | Finance user with Domain Admin | T1098.003 Cloud Roles |
| 7 | **Token Abuse** | Expired/read-only token performing writes | T1550.001 App Access Token |
| 8 | **Unused Permissions** | >50% granted permissions never exercised | T1078 Valid Accounts |

### Risk Scoring Formula

```
Score = min(base_weight × multiplier_product, 100)

Base Weights:
  Offboarding Failure: 60    (most critical — immediate breach risk)
  Dormant Admin:       55    (high — sleeping privilege time bomb)
  Token Abuse:         55    (high — active exploitation indicator)
  Privilege Spike:     50    (high — potential lateral movement)
  Excessive Perms:     45    (medium-high — violation of least privilege)
  Orphaned Account:    40    (medium — unknown attack surface)
  Cross-Platform:      35    (medium — incomplete revocation)
  Unused Permissions:  30    (lower — hygiene issue)

Multipliers (stacking):
  × 1.5 if admin account
  × 1.4 if accesses PII (Finance/HR department)
  × 1.3 if production environment
  × 1.3 if MFA disabled
  × 1.2 if multi-platform
  × 1.2 if service account
  × 1.4 if expired token
  × 1.6 if dormant >180 days
```

**Example:** Offboarding failure (60) × admin (1.5) × offboarding multiplier (1.5) = 100 → **CRITICAL**

### False Positive Prevention
- 24 accounts have documented `justification` (ITSM ticket references)
- These are excluded from detection rules
- Prevents "alert fatigue" on legitimately-approved elevated access
- Demonstrates **governance-aware detection**

---

## 5. Key Metrics & Results (2 minutes)

| Metric | Target | Achieved |
|--------|--------|----------|
| Identity Coverage | ≥95% | **100%** (272/272 assessed) |
| Detection Categories | ≥6 | **8 categories** |
| Alert Consolidation | ≥40% | **74.6%** (283 → 72 incidents) |
| Risk Explainability | Traceable | **Every finding has evidence dict** |
| Compliance Mapping | Multiple frameworks | **6 frameworks + MITRE** |
| Audit Events | 500-1000 | **974 events** |
| Offboarding Records | 50-100 | **55 records** |
| False Positive Traps | 15-20% | **~10% justified exceptions** |

### Data Scale

| Entity | Count |
|--------|-------|
| People (HR records) | 250 |
| Platform accounts | 630 |
| Unified identities | 272 |
| Service accounts | 33 |
| Groups/Roles | 41 |
| Audit events | 974 |
| Risk findings | 283 |
| Clustered incidents | 72 |

---

## 6. Live Demo Script (5 minutes)

### Step 1: Start the application
```bash
cd identity-sprawl-detector
python3 app.py
# Open http://localhost:5000
```

### Step 2: Dashboard Overview
- Point out the **8 summary cards** at top (identities, findings, critical, alert reduction)
- Show the **privilege graph** — color-coded nodes (blue=identity, red=high-risk, purple=privileged groups)
- Note the **74.6% alert consolidation** metric

### Step 3: Interactive Graph
- Click "Risky Only" button to filter graph to high-risk nodes
- Click on a **red identity node** → right panel loads cross-platform detail
- Show how the graph traces from identity → groups → permissions

### Step 4: Risk Register
- Show sortable table with all 283 findings
- Filter by **"Offboarding Failure"** — show critical findings
- Filter by **"Token Abuse"** — show credential misuse
- Click **"Fix"** button → remediation modal with platform-specific commands

### Step 5: Identity Detail Panel
- Show **cross-platform status matrix** (AD: disabled, AWS: active, Okta: active)
- Show **effective permissions** computed via graph traversal
- Show **MITRE ATT&CK technique** tags on findings
- Show **remediation commands** with compliance references

### Step 6: API Endpoints (for technical panelists)
- `http://localhost:5000/api/report` — Sample risk report
- `http://localhost:5000/api/compliance` — MITRE + framework mapping
- `http://localhost:5000/api/audit-events` — Audit trail

---

## 7. Compliance & Framework Alignment (2 minutes)

### NIST SP 800-53 Controls
- **AC-2**: Account Management (lifecycle, dormancy detection)
- **AC-6**: Least Privilege (excessive permissions, unused access)
- **IA-4**: Identifier Management (cross-platform resolution)
- **IA-5**: Authenticator Management (token abuse detection)
- **PS-4**: Personnel Termination (offboarding failures)

### MITRE ATT&CK Techniques (10 mapped)
- **T1078**: Valid Accounts (all credential-based findings)
- **T1098**: Account Manipulation (privilege escalation)
- **T1528**: Steal Application Access Token
- **T1550**: Use Alternate Authentication Material (token abuse)

### Additional Frameworks
- **CIS Controls** 5.1-5.4, 6.1, 6.5, 6.8
- **GDPR** Art. 5, 17, 32 (data minimisation, right to erasure)
- **ISO 27001** A.9.2.5, A.9.2.6, A.9.4.1, A.9.4.2
- **SOX** Section 302, 404 (internal controls)

---

## 8. What Makes This Production-Ready (2 minutes)

### Already Implemented
- Platform-specific remediation (actual CLI commands, not vague advice)
- Justification-aware detection (reduces SOC workload)
- Alert clustering (74.6% noise reduction)
- Compliance-mapped findings (audit-ready output)
- Interactive graph visualization (SOC analyst workflow)

### Production Extensions (if we had more time)
- Real API connectors (Microsoft Graph, AWS SDK, Okta API)
- Isolation Forest anomaly detection for behavioral baselines
- LLM-powered incident narratives (auto-summarize for executives)
- SOAR integration (auto-execute remediation via ServiceNow)
- Historical trend tracking (risk score over time)

---

## 9. Q&A Preparation

### "Why rules instead of ML?"
For a 48-hour hackathon, rules give us:
- **Explainability**: Compliance teams need to trace WHY an alert fired
- **Determinism**: Same data = same results (reproducible audits)
- **No training data needed**: ML requires months of labeled historical data
- **Faster iteration**: We can add/tune rules in minutes

### "How does identity resolution work?"
1. **Phase 1**: Exact email match (john.smith@sg.com appears on all 3 platforms → merge)
2. **Phase 2**: Fuzzy matching (SequenceMatcher ≥0.75 threshold) for different username formats

### "What about false positives?"
- 24 accounts have documented ITSM-approved justification
- Detection rules skip justified accounts
- Service accounts with valid tickets are excluded
- This mirrors real PAM (Privileged Access Management) workflows

### "How does the graph help?"
- Reveals **hidden effective privileges** through nested group membership
- AD: `Enterprise Admins → Domain Admins → Server Operators`
- Shows **transitive access** a flat permission list would miss
- BFS traversal computes actual effective permissions per identity

### "Can this scale to 5000+ identities?"
- NetworkX handles graphs with 100K+ nodes efficiently
- Detection rules are O(n) per identity — linear scaling
- For production: swap in-memory to Redis/Neo4j, add pagination

---

## 10. Closing Statement

> "We built a system that takes the chaos of 272 identities spread across 3 platforms, resolves them into unified profiles, traces their actual privileges through nested group hierarchies, detects 8 categories of risk using explainable rules, clusters 283 raw alerts into 72 actionable incidents, and provides platform-specific remediation commands — all mapped to NIST, MITRE ATT&CK, GDPR, and 3 other frameworks. This is what identity governance looks like when it's done right."
