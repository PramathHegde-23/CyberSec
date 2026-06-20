# Demo Walkthrough Script
## Step-by-step guide for live panel demonstration

---

## Pre-Demo Setup

```bash
cd "/Users/glaxmees/Hackathon Cybersec/identity-sprawl-detector"
python3 app.py
```

Expected console output:
```
[*] Generating synthetic identity data (250+ identities)...
[*] Resolving cross-platform identities...
[*] Building privilege graph...
[*] Running risk detection engine (8 rules)...
[*] Scoring findings...
[*] Clustering incidents...
[+] Ready: 272 identities, 283 findings, 72 incidents (84 critical, 18 high)
[+] Detection: 8 categories, alert consolidation: 75%, audit events: 974
```

Open: **http://localhost:5000**

---

## Demo Flow (10-12 minutes total)

### Scene 1: The Problem (30 seconds)

**Say:** "Imagine you're a SOC analyst at Societe Generale. You have 272 identities spread across Active Directory, AWS, and Okta. People have different usernames on each platform. When someone leaves, their AD account gets disabled but their AWS admin access stays active. How do you find these gaps?"

**Point to:** The summary cards showing 272 identities, 283 findings, 84 critical.

---

### Scene 2: Executive Dashboard (1 minute)

**Point to the 8 summary cards:**
- "272 unified identities resolved from 630 platform accounts"
- "283 risk findings detected automatically"
- "84 critical findings requiring immediate action"
- "74.6% alert consolidation — we turned 283 noisy alerts into 72 actionable incidents"
- "73.5% MFA coverage — means 26.5% of accounts lack MFA"
- "974 audit events analyzed for behavioral patterns"
- "15 service accounts tracked"

---

### Scene 3: Privilege Graph (2 minutes)

**Point to the interactive graph:**
- "Each blue dot is a person. Purple diamonds are privileged groups like Domain Admins. Gray triangles are permissions."
- "Red-bordered nodes are high-risk identities. The redder, the more dangerous."

**Click "Risky Only" button:**
- "Now we see only the risky identities and their connections. Notice how some identities connect to MULTIPLE privileged groups across platforms."

**Click on a red identity node:**
- "When I click an identity, the right panel loads their complete cross-platform profile."
- Point to the detail panel showing AD/AWS/Okta status matrix.

---

### Scene 4: Cross-Platform Identity Resolution (1 minute)

**In the identity detail panel, point out:**
- "This person has THREE different usernames: `jsmith` in AD, `john.smith` in AWS, `john.smith@sg.com` in Okta"
- "Our resolver matched them by email first, then used fuzzy matching for edge cases"
- "Their AD account is DISABLED but AWS and Okta are still ACTIVE — that's a cross-platform mismatch"

---

### Scene 5: Risk Register Deep-Dive (2 minutes)

**Scroll to risk register table:**

**Filter by "Offboarding Failure":**
- "These are terminated employees who still have active accounts. All marked CRITICAL with a score of 90+."
- "The description explains WHY: terminated employee still has active account on aws_iam."

**Filter by "Token Abuse":**
- "These are expired API tokens still being used, or read-only tokens performing write operations."
- "This maps to MITRE T1550 — Use Alternate Authentication Material."

**Filter by "Unused Permissions":**
- "These accounts have permissions they never exercise — violates least privilege."
- "Some users have 15 permissions granted but only use 4. We flag >50% unused."

**Clear filters to show all 283 findings:**
- "Without our clustering, a SOC analyst would see 283 individual alerts. With incident clustering, they see 72 actionable incidents."

---

### Scene 6: Remediation Commands (2 minutes)

**Click "Fix" button on an Offboarding Failure finding:**

**Show the remediation modal:**
- "We generate platform-specific CLI commands. Not vague advice — actual commands."
- "For Active Directory: `Disable-ADAccount`, remove from all groups"
- "For AWS: `delete-login-profile`, delete access keys, detach all policies"
- "Each remediation maps to compliance controls: NIST PS-4, GDPR Art.17, CIS 5.4"

**Point to the SLA:**
- "Critical findings get 4-hour SLA. High gets 24 hours. Medium gets 7 days."

---

### Scene 7: Compliance & MITRE Mapping (1 minute)

**Open a new tab to:** `http://localhost:5000/api/compliance`

**Explain:**
- "Every finding maps to NIST SP 800-53, CIS Controls, GDPR, ISO 27001, and SOX"
- "Plus MITRE ATT&CK: 10 techniques mapped including T1078 Valid Accounts, T1098 Account Manipulation, T1550 Token Abuse"
- "This makes findings audit-ready — compliance team can immediately see which controls are violated"

---

### Scene 8: Sample Risk Report (1 minute)

**Open:** `http://localhost:5000/api/report`

**Explain:**
- "This is the executive report endpoint — top 10 riskiest identities with full details"
- "Each entry has: identity name, risk score, all platforms, findings, and specific remediation"
- "The executive summary shows 100% identity coverage and the 8 recommendations"

---

### Scene 9: False Positive Handling (30 seconds)

**Say:** "Not all high-privilege accounts are dangerous. 24 accounts in our system have documented justification — approved ITSM tickets. These are EXCLUDED from detection. This prevents alert fatigue and shows governance awareness."

---

### Scene 10: Closing (30 seconds)

**Say:** "To summarize: We take chaotic multi-platform identity data, resolve it into unified profiles, compute effective privileges through graph traversal, detect 8 categories of risk, score them with weighted multipliers, cluster 283 alerts into 72 incidents, and provide executable remediation commands — all mapped to 6 compliance frameworks. Questions?"

---

## Backup: API Endpoints to Show

If panelists want to see raw data:

| What to Show | URL |
|-------------|-----|
| Dashboard stats | http://localhost:5000/api/dashboard/summary |
| All risks (JSON) | http://localhost:5000/api/risks |
| Audit events | http://localhost:5000/api/audit-events?limit=10 |
| MITRE + Compliance | http://localhost:5000/api/compliance |
| Risk report | http://localhost:5000/api/report |
| Graph data | http://localhost:5000/api/graph |

---

## Potential Panel Questions & Answers

**Q: "What if someone has no email in one platform?"**
A: Phase 2 fuzzy matching uses display name similarity (SequenceMatcher ≥0.75) and username component matching. If `jsmith` contains parts of "John Smith", we can still resolve it.

**Q: "How do you handle service accounts?"**
A: Service accounts are tagged with `is_service_account=True`. Those with ITSM-approved justification are excluded from findings. Unjustified service accounts with admin access are flagged.

**Q: "Why not use ML?"**
A: Three reasons: (1) Explainability — compliance teams need to audit WHY alerts fire; (2) No training data needed — we detect on day one; (3) Determinism — same input = same output, critical for reproducible audits.

**Q: "What's the alert consolidation metric?"**
A: We measure `1 - (incidents / findings)`. 283 findings → 72 incidents = 74.6% reduction. Target was ≥40%. We exceeded it because our clustering merges per-identity and per-category findings.

**Q: "How would this work in production?"**
A: Replace Faker data with real API connectors (Microsoft Graph for AD, boto3 for AWS, Okta SDK). The detection engine, scoring, and clustering logic remain identical. Add a scheduler for periodic scans.
