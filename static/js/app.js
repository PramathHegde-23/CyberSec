/**
 * Main orchestrator for Identity Sprawl Detector dashboard.
 */

document.addEventListener('DOMContentLoaded', () => {
    loadDashboard();
});

async function loadDashboard() {
    try {
        const [summary, risks, incidents] = await Promise.all([
            fetch('/api/dashboard/summary').then(r => r.json()),
            fetch('/api/risks').then(r => r.json()),
            fetch('/api/incidents').then(r => r.json()),
        ]);

        renderSummaryCards(summary);
        renderHeaderStats(summary);
        initGraph();
        initRiskTable(risks.findings);
        renderIncidents(incidents.incidents);
        setupFilters();
    } catch (err) {
        console.error('Dashboard load failed:', err);
    }
}

function renderSummaryCards(summary) {
    const container = document.getElementById('summary-cards');
    const cards = [
        { value: summary.total_identities, label: 'Identities', class: '' },
        { value: summary.total_findings, label: 'Risk Findings', class: '' },
        { value: summary.severity_counts.critical, label: 'Critical', class: 'stat-critical' },
        { value: summary.severity_counts.high, label: 'High', class: 'stat-high' },
        { value: summary.alert_consolidation_ratio + '%', label: 'Alert Reduction', class: 'stat-medium' },
        { value: summary.mfa_coverage.percentage + '%', label: 'MFA Coverage', class: summary.mfa_coverage.percentage < 80 ? 'stat-high' : 'stat-medium' },
        { value: summary.audit_events_count, label: 'Audit Events', class: '' },
        { value: summary.service_accounts, label: 'Service Accts', class: '' },
    ];

    container.innerHTML = cards.map(c => `
        <div class="col">
            <div class="stat-card">
                <div class="stat-value ${c.class}">${c.value}</div>
                <div class="stat-label">${c.label}</div>
            </div>
        </div>
    `).join('');
}

function renderHeaderStats(summary) {
    const container = document.getElementById('header-stats');
    const platforms = summary.platform_counts;
    container.innerHTML = Object.entries(platforms).map(([p, count]) => `
        <span class="badge platform-${p}">${p.replace('_', ' ')}: ${count}</span>
    `).join('');
}

function renderIncidents(incidents) {
    const container = document.getElementById('incidents-list');
    if (!incidents || incidents.length === 0) {
        container.innerHTML = '<p class="text-muted">No clustered incidents detected.</p>';
        return;
    }

    container.innerHTML = incidents.slice(0, 10).map(incident => `
        <div class="incident-card severity-${incident.severity}">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h6 class="mb-1">${incident.title}</h6>
                    <small class="text-muted">
                        Root cause: ${incident.root_cause} |
                        Affected: ${incident.affected_identities.length} identities |
                        Findings: ${incident.findings.length}
                    </small>
                </div>
                <div class="text-end">
                    <span class="badge badge-${incident.severity}">${incident.severity.toUpperCase()}</span>
                    <div class="mt-1"><small class="text-muted">Score: ${incident.aggregate_score.toFixed(1)}</small></div>
                </div>
            </div>
            ${incident.remediation_steps.length > 0 ? `
                <div class="mt-2">
                    <small class="text-muted">Remediation: ${incident.remediation_steps.join(', ')}</small>
                </div>
            ` : ''}
        </div>
    `).join('');
}

function setupFilters() {
    document.getElementById('filter-category').addEventListener('change', applyFilters);
    document.getElementById('filter-severity').addEventListener('change', applyFilters);
}

async function applyFilters() {
    const category = document.getElementById('filter-category').value;
    const severity = document.getElementById('filter-severity').value;

    let url = '/api/risks?';
    if (category) url += `category=${category}&`;
    if (severity) url += `severity=${severity}&`;

    const data = await fetch(url).then(r => r.json());
    updateRiskTable(data.findings);
}
