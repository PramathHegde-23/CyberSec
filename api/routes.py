"""Flask REST API endpoints."""

from flask import Blueprint, jsonify, request

api_bp = Blueprint("api", __name__, url_prefix="/api")

_state = {
    "unified_identities": [],
    "findings": [],
    "incidents": [],
    "graph": None,
    "groups": [],
    "people": [],
    "audit_events": [],
}


def init_state(unified_identities, findings, incidents, graph, groups, people, audit_events=None):
    """Initialize API state with computed data."""
    _state["unified_identities"] = unified_identities
    _state["findings"] = findings
    _state["incidents"] = incidents
    _state["graph"] = graph
    _state["groups"] = groups
    _state["people"] = people
    _state["audit_events"] = audit_events or []


@api_bp.route("/dashboard/summary")
def dashboard_summary():
    """Executive dashboard summary stats."""
    identities = _state["unified_identities"]
    findings = _state["findings"]
    incidents = _state["incidents"]
    audit_events = _state["audit_events"]

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        severity_counts[f.severity.value] += 1

    category_counts = {}
    for f in findings:
        cat = f.category.value
        category_counts[cat] = category_counts.get(cat, 0) + 1

    platform_counts = {}
    for identity in identities:
        for platform in identity.platform_accounts:
            platform_counts[platform] = platform_counts.get(platform, 0) + 1

    high_risk = [i for i in identities if i.risk_score >= 60]
    service_accounts = [i for i in identities if i.is_service_account]
    justified = [i for i in identities if i.has_justification]

    # Alert consolidation metric
    consolidation = 1 - (len(incidents) / max(len(findings), 1))

    return jsonify({
        "total_identities": len(identities),
        "total_findings": len(findings),
        "total_incidents": len(incidents),
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "platform_counts": platform_counts,
        "high_risk_identities": len(high_risk),
        "avg_risk_score": round(sum(i.risk_score for i in identities) / max(len(identities), 1), 1),
        "mfa_coverage": _mfa_stats(identities),
        "service_accounts": len(service_accounts),
        "justified_exceptions": len(justified),
        "alert_consolidation_ratio": round(consolidation * 100, 1),
        "audit_events_count": len(audit_events),
        "identity_coverage": round(len([i for i in identities if i.findings or i.risk_score == 0]) / max(len(identities), 1) * 100, 1),
    })


@api_bp.route("/identities")
def list_identities():
    """List all unified identities with summary info."""
    identities = _state["unified_identities"]
    limit = int(request.args.get("limit", 50))

    sorted_ids = sorted(identities, key=lambda i: i.risk_score, reverse=True)

    return jsonify({
        "total": len(sorted_ids),
        "identities": [
            {
                "id": i.id,
                "display_name": i.display_name,
                "email": i.primary_email,
                "department": i.department,
                "risk_score": i.risk_score,
                "platforms": list(i.platform_accounts.keys()),
                "finding_count": len(i.findings),
                "is_service_account": i.is_service_account,
                "has_justification": i.has_justification,
            }
            for i in sorted_ids[:limit]
        ],
    })


@api_bp.route("/identities/<identity_id>")
def get_identity(identity_id):
    """Get detailed information for a specific identity."""
    identity = _find_identity(identity_id)
    if not identity:
        return jsonify({"error": "Identity not found"}), 404

    from engine.privilege_graph import get_effective_permissions
    graph = _state["graph"]
    permissions = get_effective_permissions(graph, identity_id) if graph and identity_id in graph else []

    from engine.remediation import generate_remediation
    remediation_data = []
    for finding in identity.findings:
        remediation_data.append(generate_remediation(finding))

    result = identity.to_dict()
    result["effective_permissions"] = permissions
    result["remediation"] = remediation_data

    return jsonify(result)


@api_bp.route("/graph")
def get_full_graph():
    """Get full privilege graph for vis.js rendering."""
    from engine.privilege_graph import export_graph_json
    graph = _state["graph"]
    if not graph:
        return jsonify({"nodes": [], "edges": []})
    return jsonify(export_graph_json(graph))


@api_bp.route("/graph/identity/<identity_id>")
def get_identity_graph(identity_id):
    """Get subgraph centered on a specific identity."""
    from engine.privilege_graph import get_identity_subgraph
    graph = _state["graph"]
    if not graph:
        return jsonify({"nodes": [], "edges": []})
    return jsonify(get_identity_subgraph(graph, identity_id))


@api_bp.route("/risks")
def list_risks():
    """List all risk findings with filtering."""
    findings = _state["findings"]
    category = request.args.get("category")
    severity = request.args.get("severity")
    platform = request.args.get("platform")

    filtered = findings
    if category:
        filtered = [f for f in filtered if f.category.value == category]
    if severity:
        filtered = [f for f in filtered if f.severity.value == severity]
    if platform:
        filtered = [f for f in filtered if platform in f.platform]

    sorted_findings = sorted(filtered, key=lambda f: f.score, reverse=True)

    return jsonify({
        "total": len(sorted_findings),
        "findings": [f.to_dict() for f in sorted_findings],
    })


@api_bp.route("/incidents")
def list_incidents():
    """List clustered incidents."""
    incidents = _state["incidents"]
    return jsonify({
        "total": len(incidents),
        "incidents": [i.to_dict() for i in incidents],
    })


@api_bp.route("/audit-events")
def list_audit_events():
    """List recent audit events with filtering."""
    events = _state["audit_events"]
    event_type = request.args.get("type")
    limit = int(request.args.get("limit", 100))

    if event_type:
        events = [e for e in events if e.event_type.value == event_type]

    return jsonify({
        "total": len(events),
        "events": [e.to_dict() for e in events[:limit]],
        "event_types": list(set(e.event_type.value for e in _state["audit_events"])),
    })


@api_bp.route("/compliance")
def compliance_report():
    """Compliance framework mapping for all findings."""
    findings = _state["findings"]

    frameworks = {}
    for finding in findings:
        for ref in finding.compliance_refs:
            framework = ref.split(" ")[0]
            if framework not in frameworks:
                frameworks[framework] = {"controls": {}, "finding_count": 0}
            frameworks[framework]["finding_count"] += 1
            frameworks[framework]["controls"][ref] = frameworks[framework]["controls"].get(ref, 0) + 1

    # MITRE ATT&CK mapping
    mitre_techniques = {}
    for finding in findings:
        for ref in finding.mitre_refs:
            technique_id = ref.split(" - ")[0]
            if technique_id not in mitre_techniques:
                mitre_techniques[technique_id] = {"name": ref, "finding_count": 0, "categories": []}
            mitre_techniques[technique_id]["finding_count"] += 1
            if finding.category.value not in mitre_techniques[technique_id]["categories"]:
                mitre_techniques[technique_id]["categories"].append(finding.category.value)

    return jsonify({
        "total_findings": len(findings),
        "frameworks": frameworks,
        "mitre_attack": mitre_techniques,
        "coverage": {
            "nist_800_53": any("NIST" in r for f in findings for r in f.compliance_refs),
            "cis_controls": any("CIS" in r for f in findings for r in f.compliance_refs),
            "gdpr": any("GDPR" in r for f in findings for r in f.compliance_refs),
            "iso_27001": any("ISO" in r for f in findings for r in f.compliance_refs),
            "sox": any("SOX" in r for f in findings for r in f.compliance_refs),
            "mitre_attack": len(mitre_techniques) > 0,
        },
    })


@api_bp.route("/report")
def sample_risk_report():
    """Generate sample risk report with top 10 risky identities."""
    identities = _state["unified_identities"]
    findings = _state["findings"]
    incidents = _state["incidents"]

    top_risky = sorted(identities, key=lambda i: i.risk_score, reverse=True)[:10]

    report_entries = []
    for identity in top_risky:
        platforms = {}
        for p, acc in identity.platform_accounts.items():
            platforms[p] = {
                "username": acc.username,
                "status": acc.status.value,
                "is_admin": acc.is_admin,
                "mfa_enabled": acc.mfa_enabled,
                "last_login": acc.last_login.isoformat() if acc.last_login else None,
            }

        from engine.remediation import generate_remediation
        remediation = []
        for f in identity.findings:
            r = generate_remediation(f)
            remediation.append({
                "finding": f.title,
                "severity": f.severity.value,
                "commands": r["commands"],
                "compliance": r["compliance"],
                "mitre": f.mitre_refs,
                "sla": r["sla"],
            })

        report_entries.append({
            "rank": len(report_entries) + 1,
            "identity": identity.display_name,
            "email": identity.primary_email,
            "department": identity.department,
            "risk_score": identity.risk_score,
            "platforms": platforms,
            "finding_count": len(identity.findings),
            "findings_summary": [f.title for f in identity.findings],
            "remediation": remediation,
        })

    # Severity distribution
    severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        severity_dist[f.severity.value] += 1

    # Category breakdown
    category_dist = {}
    for f in findings:
        category_dist[f.category.value] = category_dist.get(f.category.value, 0) + 1

    return jsonify({
        "report_title": "Identity Sprawl Risk Assessment Report",
        "generated_at": __import__("datetime").datetime.now().isoformat(),
        "executive_summary": {
            "total_identities_assessed": len(identities),
            "total_findings": len(findings),
            "critical_findings": severity_dist["critical"],
            "high_findings": severity_dist["high"],
            "incidents_clustered": len(incidents),
            "alert_consolidation": f"{(1 - len(incidents) / max(len(findings), 1)) * 100:.0f}%",
            "identity_coverage": "100%",
        },
        "severity_distribution": severity_dist,
        "category_distribution": category_dist,
        "top_10_risky_identities": report_entries,
        "recommendations": [
            "Immediately disable all offboarding failure accounts (Critical SLA: 4 hours)",
            "Revoke dormant admin privileges and require MFA re-enrollment",
            "Investigate privilege spike events for unauthorized escalation",
            "Remediate cross-platform status mismatches to close revocation gaps",
            "Rotate or revoke all expired/abused API tokens",
            "Right-size unused permissions based on access review",
            "Document justification for all legitimate high-privilege accounts",
            "Implement automated offboarding workflow across all platforms",
        ],
    })


def _find_identity(identity_id):
    for i in _state["unified_identities"]:
        if i.id == identity_id:
            return i
    return None


def _mfa_stats(identities):
    total = 0
    enabled = 0
    for identity in identities:
        for account in identity.platform_accounts.values():
            total += 1
            if account.mfa_enabled:
                enabled += 1
    return {
        "total_accounts": total,
        "mfa_enabled": enabled,
        "percentage": round((enabled / max(total, 1)) * 100, 1),
    }
