# Risk Scoring System — Detailed Explanation

---

## Overview

Our scoring system converts raw detection findings into a normalized 0-100 risk score that enables:
- **Prioritization**: SOC teams handle critical (80+) before medium (40-60)
- **Comparison**: Compare risk across identities, platforms, and time
- **SLA assignment**: Critical = 4hr, High = 24hr, Medium = 7d, Low = 30d

---

## Scoring Formula

```
Finding Score = min(base_weight × Π(multipliers), 100)
```

Where `Π(multipliers)` is the product of all applicable multiplier values.

---

## Base Weights (by category)

| Category | Base Weight | Rationale |
|----------|------------|-----------|
| Offboarding Failure | 60 | Immediate breach risk — terminated person retains access |
| Dormant Admin | 55 | Sleeping privilege bomb — unused admin = attack vector |
| Token Abuse | 55 | Active exploitation indicator — compromised credential |
| Privilege Spike | 50 | Potential lateral movement — sudden escalation |
| Excessive Permissions | 45 | Least privilege violation — unnecessary attack surface |
| Orphaned Account | 40 | Unknown ownership — no one monitoring this account |
| Cross-Platform Mismatch | 35 | Incomplete revocation — partial deprovisioning |
| Unused Permissions | 30 | Hygiene issue — not immediate threat but expandable surface |

---

## Multipliers (cumulative)

| Condition | Multiplier | Rationale |
|-----------|-----------|-----------|
| Account is admin | ×1.5 | Admin compromise = full domain/cloud takeover |
| Dormant >180 days | ×1.6 | Extremely stale — likely forgotten, easy target |
| Dormant >120 days | ×1.3 | Very stale — should have been caught in review |
| Offboarding category | ×1.5 | Terminated = zero business justification |
| No MFA enabled (admin) | ×1.3 | Single factor = easily phishable |
| PII department (Finance/HR) | ×1.4 | Accesses sensitive employee/financial data |
| Production environment | ×1.3 | Impacts live systems and customers |
| Multi-platform finding | ×1.2 | Broader blast radius across infrastructure |
| Service account | ×1.2 | Often has elevated perms, harder to rotate |
| Expired token (active) | ×1.4 | Indicates compromised credential in use |

---

## Severity Thresholds

| Score Range | Severity | SLA | Action |
|-------------|----------|-----|--------|
| 80 - 100 | CRITICAL | 4 hours | Immediate disable/revoke |
| 60 - 79 | HIGH | 24 hours | Same-day remediation |
| 40 - 59 | MEDIUM | 7 days | Next sprint/review cycle |
| 20 - 39 | LOW | 30 days | Backlog for access review |
| 0 - 19 | INFO | — | No action required |

---

## Worked Examples

### Example 1: Terminated Finance Admin (Score: 100)
```
Category: OffboardingFailure
Base weight: 60
Multipliers:
  × 1.5 (is_admin = true)
  × 1.5 (offboarding category)
  × 1.4 (PII department: Finance)

Score = 60 × 1.5 × 1.5 × 1.4 = 189 → capped at 100
Severity: CRITICAL
SLA: 4 hours
```

### Example 2: Dormant IT Admin, 200 days, no MFA (Score: 100)
```
Category: DormantAdmin
Base weight: 55
Multipliers:
  × 1.5 (is_admin = true)
  × 1.6 (dormant > 180 days)
  × 1.3 (no MFA)

Score = 55 × 1.5 × 1.6 × 1.3 = 171.6 → capped at 100
Severity: CRITICAL
SLA: 4 hours
```

### Example 3: Marketing User with AWS Admin (Score: 94.5)
```
Category: ExcessivePermissions
Base weight: 45
Multipliers:
  × 1.5 (is_admin = true)
  × 1.4 (PII-adjacent department)

Score = 45 × 1.5 × 1.4 = 94.5
Severity: CRITICAL
SLA: 4 hours
```

### Example 4: Expired Token Used Recently (Score: 77)
```
Category: TokenAbuse
Base weight: 55
Multipliers:
  × 1.4 (expired token active use)

Score = 55 × 1.4 = 77
Severity: HIGH
SLA: 24 hours
```

### Example 5: Unused Permissions (non-admin) (Score: 30)
```
Category: UnusedPermissions
Base weight: 30
Multipliers: none apply

Score = 30
Severity: LOW
SLA: 30 days
```

---

## Identity Aggregate Score

Individual identities may have multiple findings. The aggregate score reflects compound risk:

```
aggregate = max_score + sum(remaining_scores × 0.15)
capped at 100
```

### Example: Identity with 3 findings
```
Findings: [100, 90, 42]
Aggregate = 100 + (90 × 0.15) + (42 × 0.15)
         = 100 + 13.5 + 6.3
         = 119.8 → capped at 100
```

### Why 15% for additional findings?
- **Too high (e.g., 50%)**: Every identity with 3+ findings would be CRITICAL regardless of actual risk
- **Too low (e.g., 5%)**: Additional findings barely matter, compound risk undervalued
- **15% balance**: Additional findings meaningfully increase score without overwhelming

---

## Alert Consolidation Metric

```
Consolidation = 1 - (incidents / findings)

Our result: 1 - (72 / 283) = 74.6%
```

This means the SOC team sees **74.6% fewer items** to triage compared to raw finding output.

---

## Comparison with Industry Standards

| Our Approach | CVSS | Similarity |
|-------------|------|-----------|
| Base weight per category | Base Score | Both start with inherent severity |
| Admin multiplier | Privileges Required (PR) | Both consider privilege level |
| Multi-platform | Scope (S) | Both consider blast radius |
| No MFA | Attack Complexity (AC) | Both consider exploitability |

We specifically add:
- **Dormancy multiplier** (CVSS has no concept of time-based risk)
- **PII department** (CVSS doesn't consider data sensitivity at scoring time)
- **Justification exclusion** (no CVSS equivalent for mitigating controls)
