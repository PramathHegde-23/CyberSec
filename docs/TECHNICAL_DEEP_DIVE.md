# Technical Deep-Dive: Identity Sprawl Detector

---

## 1. System Architecture

### Component Interaction Flow

```
                    ┌──────────────┐
                    │   Browser    │
                    │  (vis.js +   │
                    │  DataTables) │
                    └──────┬───────┘
                           │ HTTP
                           ▼
                    ┌──────────────┐
                    │  Flask App   │
                    │  (app.py)    │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
      ┌──────────┐  ┌──────────┐  ┌──────────┐
      │ API      │  │ Template │  │ Static   │
      │ Routes   │  │ Render   │  │ Assets   │
      └────┬─────┘  └──────────┘  └──────────┘
           │
    ┌──────┼──────────────────────────┐
    │      ▼                          │
    │  ┌─────────────────────┐        │
    │  │  Detection Engine   │        │
    │  │  ┌───────────────┐  │        │
    │  │  │ 8 Rule Engine │  │        │
    │  │  └───────┬───────┘  │        │
    │  │          ▼          │        │
    │  │  ┌───────────────┐  │        │
    │  │  │ Risk Scorer   │  │        │
    │  │  └───────┬───────┘  │        │
    │  │          ▼          │        │
    │  │  ┌───────────────┐  │        │
    │  │  │ Incident      │  │        │
    │  │  │ Clusterer     │  │        │
    │  │  └───────┬───────┘  │        │
    │  │          ▼          │        │
    │  │  ┌───────────────┐  │        │
    │  │  │ Remediation   │  │        │
    │  │  │ Generator     │  │        │
    │  │  └───────────────┘  │        │
    │  └─────────────────────┘        │
    │                                  │
    │  ┌─────────────────────┐        │
    │  │  Identity Layer     │        │
    │  │  ┌───────────────┐  │        │
    │  │  │ Resolver      │  │        │
    │  │  │ (email+fuzzy) │  │        │
    │  │  └───────┬───────┘  │        │
    │  │          ▼          │        │
    │  │  ┌───────────────┐  │        │
    │  │  │ Privilege     │  │        │
    │  │  │ Graph (NX)    │  │        │
    │  │  └───────────────┘  │        │
    │  └─────────────────────┘        │
    │                                  │
    │  ┌─────────────────────┐        │
    │  │  Data Generation    │        │
    │  │  250 people + 33    │        │
    │  │  service accounts + │        │
    │  │  974 audit events   │        │
    │  └─────────────────────┘        │
    └──────────────────────────────────┘
```

---

## 2. Identity Resolution Algorithm

### Problem
The same person has different identifiers on each platform:
- **AD**: `jsmith` (first initial + last name)
- **AWS**: `john.smith` or `john_smith` (first.last)
- **Okta**: `john.smith@societe-generale.com` (email as username)

### Solution: Two-Phase Resolution

#### Phase 1: Exact Email Match
```python
# Group all accounts by email
email_groups = {}
for account in all_accounts:
    email_groups.setdefault(account.email, []).append(account)

# Accounts sharing email → same person
for email, accounts in email_groups.items():
    unified.append(merge_accounts(accounts))
```

#### Phase 2: Fuzzy Matching (for accounts without email match)
```python
def compute_similarity(account, identity):
    scores = []

    # Display name similarity (weighted 1.5×)
    name_score = SequenceMatcher(None,
        account.display_name.lower(),
        identity.display_name.lower()
    ).ratio()
    scores.append(name_score * 1.5)

    # Username contains name parts
    name_parts = identity.display_name.lower().split()
    username = account.username.lower().replace(".", " ").replace("_", " ")
    for part in name_parts:
        if part in username:
            scores.append(0.6)
            break

    # Department match bonus
    if account.department == identity.department:
        scores.append(0.3)

    return average(scores)  # Threshold: 0.75
```

---

## 3. Privilege Graph & Effective Permissions

### Graph Structure (NetworkX DiGraph)
```
Node Types:
  - identity (272 nodes) — unified person/service account
  - group (41 nodes) — AD groups, AWS roles, Okta groups
  - permission (varies) — individual access rights

Edge Types:
  - member_of: identity → group
  - has_role: identity → AWS role
  - grants: group → permission
  - inherits_from: group → parent group

Total: 332 nodes, 1910 edges
```

### Group Inheritance Hierarchy
```
AD:
  Enterprise Admins
    └── Domain Admins (inherits all Enterprise Admin perms)
         ├── Server Operators
         └── Backup Operators

AWS:
  AdministratorAccess
    └── PowerUserAccess
         └── ReadOnlyAccess

Okta:
  IT-Admins
    └── Privileged-Access
```

### Effective Permission Calculation (BFS)
```python
def get_effective_permissions(graph, identity_id):
    """Traverse graph to find ALL reachable permissions."""
    permissions = set()
    visited = set()
    queue = [identity_id]

    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        for _, target, data in graph.out_edges(current, data=True):
            node_type = graph.nodes[target].get("type")
            if node_type == "permission":
                permissions.add(graph.nodes[target]["label"])
            elif node_type in ("group", "role"):
                queue.append(target)  # Follow group hierarchy

    return list(permissions)
```

**Why this matters:** A user in `Domain Admins` actually has permissions from `Server Operators` AND `Backup Operators` through inheritance. Flat permission lists miss this.

---

## 4. Detection Rules — Implementation Details

### Rule 1: Orphaned Account Detection
```
Input: All unified identities + HR employee list
Logic:
  IF account.email NOT IN hr_emails
  AND account.status == ACTIVE
  AND account.is_service_account == False
  AND account.justification == empty
  THEN → finding(OrphanedAccount)
```

### Rule 2: Dormant Admin Detection
```
Input: All admin accounts with last_login timestamp
Logic:
  IF account.is_admin == True
  AND account.status == ACTIVE
  AND (now - last_login).days >= 90
  AND account.justification == empty
  THEN → finding(DormantAdmin)

  Severity: CRITICAL if >180 days, HIGH if >90 days
```

### Rule 3: Privilege Spike Detection
```
Input: AWS accounts with privilege change markers
Logic:
  IF "escalated:" in account.permissions
  AND "AdministratorAccess" in account.roles
  AND account.justification == empty
  THEN → finding(PrivilegeSpike)
```

### Rule 4: Cross-Platform Mismatch Detection
```
Input: Identities with accounts on 2+ platforms
Logic:
  IF any_platform.status == DISABLED
  AND other_platform.status == ACTIVE
  THEN → finding(CrossPlatformMismatch)

  Example: AD disabled, AWS active → incomplete offboarding
```

### Rule 5: Offboarding Failure Detection
```
Input: Terminated employee list + all accounts
Logic:
  IF identity.email IN terminated_emails
  AND any_account.status == ACTIVE
  THEN → finding(OffboardingFailure, severity=CRITICAL)
```

### Rule 6: Excessive Permissions Detection
```
Input: Non-technical department accounts with admin access
Logic:
  IF identity.department IN (Finance, HR, Marketing, Sales, Legal)
  AND account.is_admin == True
  AND account.groups INTERSECTS privileged_admin_roles
  AND account.justification == empty
  THEN → finding(ExcessivePermissions)
```

### Rule 7: Token/Credential Abuse Detection
```
Input: Accounts with API tokens
Logic:
  Case A - Expired token still used:
    IF token.is_expired == True
    AND token.last_used is recent
    THEN → finding(TokenAbuse)

  Case B - Scope violation:
    IF token.scope == "read"
    AND token.scope_violation == True (observed writes)
    THEN → finding(TokenAbuse, severity=CRITICAL if admin)
```

### Rule 8: Unused Permissions Detection
```
Input: Accounts with granted_permissions and used_permissions
Logic:
  unused = granted_permissions - used_permissions
  usage_ratio = len(used) / len(granted)

  IF usage_ratio < 0.5
  AND len(unused) >= 4
  AND account.justification == empty
  THEN → finding(UnusedPermissions)
```

---

## 5. Risk Scoring — Weighted Formula

### Step 1: Individual Finding Score
```python
score = base_weight × (multiplier₁ × multiplier₂ × ... × multiplierₙ)
score = min(score, 100)  # Cap at 100
```

### Step 2: Identity Aggregate Score
```python
# Sort all finding scores descending
scores = sorted([f.score for f in findings], reverse=True)

# Take max + 15% of remaining
aggregate = scores[0]
for additional_score in scores[1:]:
    aggregate += additional_score * 0.15

identity.risk_score = min(aggregate, 100)
```

### Scoring Example
```
Identity: John (Finance, terminated 10 days ago)
  Finding 1: Offboarding Failure (AD still active)
    base=60 × admin(1.5) × offboarding(1.5) = 100 → CRITICAL
  Finding 2: Offboarding Failure (AWS still active)
    base=60 × offboarding(1.5) = 90 → CRITICAL
  Finding 3: Cross-Platform Mismatch
    base=35 × multi_platform(1.2) = 42 → MEDIUM

  Aggregate = 100 + (90 × 0.15) + (42 × 0.15) = 100 (capped)
```

---

## 6. Incident Clustering Algorithm

### Goal
Reduce 283 individual findings → 72 actionable incidents (74.6% reduction)

### Two-Phase Clustering

#### Phase 1: Per-Identity Clustering
```python
# Group findings by identity
by_identity = defaultdict(list)
for finding in findings:
    by_identity[finding.identity_id].append(finding)

# Create compound incident for identities with 2+ findings
for identity_id, id_findings in by_identity.items():
    if len(id_findings) >= 2:
        incidents.append(Incident(
            title=f"Multiple risks for {identity.name}",
            root_cause="compound_risk",
            findings=id_findings
        ))
```

#### Phase 2: Systemic Issue Clustering
```python
# Group by category across all identities
by_category = defaultdict(list)
for finding in findings:
    by_category[finding.category].append(finding)

# Create systemic incident for categories with 3+ findings
for category, cat_findings in by_category.items():
    if len(cat_findings) >= 3:
        incidents.append(Incident(
            title=f"Systemic: {category} ({len(cat_findings)} findings)",
            root_cause=category,
            findings=cat_findings
        ))
```

---

## 7. Remediation Generation

### Platform-Specific Commands

#### Active Directory (PowerShell)
```powershell
# Offboarding Failure
Disable-ADAccount -Identity 'jsmith'
Set-ADUser -Identity 'jsmith' -Description 'Terminated - immediate disable'
Get-ADUser 'jsmith' -Properties MemberOf | ForEach-Object {
    $_.MemberOf | Remove-ADGroupMember -Members 'jsmith' -Confirm:$false
}
```

#### AWS IAM (AWS CLI)
```bash
# Token Abuse - Revoke and rotate
aws iam list-access-keys --user-name john.smith
aws iam update-access-key --user-name john.smith --access-key-id AKIA... --status Inactive
aws iam delete-access-key --user-name john.smith --access-key-id AKIA...
aws iam create-access-key --user-name john.smith
```

#### Okta (Okta CLI)
```bash
# Offboarding - Deactivate and revoke
okta users deactivate john.smith@societe-generale.com
okta users suspend john.smith@societe-generale.com
okta users apps list john.smith@societe-generale.com | jq -r '.[].id' | \
    xargs -I {} okta apps users remove {} john.smith@societe-generale.com
```

---

## 8. Audit Event Telemetry

### Event Distribution (974 total)
| Event Type | Count | Purpose |
|-----------|-------|---------|
| login_success | ~550 | Baseline behavior |
| resource_access | ~180 | Data access patterns |
| privilege_change | ~100 | Escalation detection |
| token_usage | ~70 | Credential monitoring |
| login_failure | ~65 | Brute force / lockout |

### Anomaly Indicators Tracked
- Login from unexpected IP (public vs private)
- SSO cascade (3 platforms in 10 minutes from same external IP)
- Token used after expiration
- Read-scoped token performing write operations
- Failed login followed by successful login from different geo

---

## 9. Frontend Visualization

### vis.js Graph Features
- **Color coding**: Blue (normal), Red (high risk), Orange (medium), Purple (privileged group), Green (normal group), Gray (permission)
- **Node shapes**: Dot (identity), Diamond (group), Triangle (permission)
- **Click interaction**: Click identity → loads detail panel + subgraph
- **Filter modes**: Full graph vs Risky-only (shows only risk-connected nodes)
- **Physics simulation**: Barnes-Hut gravity for organic layout

### Risk Table (DataTables)
- Sortable by score, severity, category, platform
- Filterable by category dropdown and severity dropdown
- "Fix" button opens remediation modal with commands
- "Inspect" button focuses graph + loads identity detail

---

## 10. API Reference

| Endpoint | Response | Use Case |
|----------|----------|----------|
| `GET /api/dashboard/summary` | Stats: identities, findings, severities, MFA, consolidation | Dashboard header |
| `GET /api/identities?limit=N` | Sorted list with risk scores | Identity list |
| `GET /api/identities/<id>` | Full detail + permissions + remediation | Detail panel |
| `GET /api/graph` | {nodes, edges} for vis.js | Full graph render |
| `GET /api/graph/identity/<id>` | Ego-graph (3 hops) | Focused view |
| `GET /api/risks?category=X&severity=Y` | Filtered findings | Risk table |
| `GET /api/incidents` | Clustered incidents | Incident view |
| `GET /api/audit-events?type=X&limit=N` | Event timeline | Audit trail |
| `GET /api/compliance` | Framework + MITRE mapping | Compliance report |
| `GET /api/report` | Top 10 risk report + recommendations | Executive summary |
