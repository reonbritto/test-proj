(function () {
    const cveId = getParam('id');
    if (!cveId) {
        showError('No CVE ID provided. Use ?id=CVE-YYYY-NNNNN');
        return;
    }

    if (!/^CVE-\d{4}-\d{4,}$/i.test(cveId)) {
        showError('Invalid CVE ID format. Expected: CVE-YYYY-NNNNN');
        return;
    }

    loadCVE(cveId.toUpperCase());
})();

async function loadCVE(cveId) {
    const loading = document.getElementById('loading');
    const content = document.getElementById('cveContent');

    try {
        const data = await fetchAPI(
            `/api/cve/${encodeURIComponent(cveId)}`
        );

        document.getElementById('cveId').textContent = data.cve_id;
        document.title = `${data.cve_id} - PureSecure`;
        document.getElementById('severityBadge').innerHTML =
            severityBadge(data.cvss.v3_score, data.cvss.v3_severity);
        document.getElementById('published').textContent =
            formatDate(data.published);
        document.getElementById('modified').textContent =
            formatDate(data.modified);

        document.getElementById('description').textContent =
            data.description;

        renderCVSS(data.cvss);
        renderCWEs(data.cwe_ids);
        renderProducts(data.affected_products);
        renderReferences(data.references);

        loading.style.display = 'none';
        content.style.display = 'block';

        loadAttackMapping(cveId);
    } catch (err) {
        showError(
            `Failed to load ${escapeHTML(cveId)}: ${escapeHTML(err.message)}`
        );
    }
}

function renderCVSS(cvss) {
    const panel = document.getElementById('cvssPanel');
    let html = '';

    if (cvss.v3_score !== null && cvss.v3_score !== undefined) {
        const color = getScoreColor(cvss.v3_score);
        html += `<div class="cvss-box">
            <h3>CVSS v3.1</h3>
            <div class="cvss-score" style="color:${color}">
                ${cvss.v3_score.toFixed(1)}
            </div>
            <div class="score-bar">
                <div class="score-bar-fill"
                     style="width:${cvss.v3_score * 10}%;
                            background:${color}"></div>
            </div>
            ${cvss.v3_vector
                ? `<div class="cvss-vector">${escapeHTML(cvss.v3_vector)}</div>`
                : ''}
            ${cvss.v3_severity
                ? `<div style="margin-top:0.5rem;">
                    ${severityBadge(cvss.v3_score, cvss.v3_severity)}
                   </div>`
                : ''}
        </div>`;
    }

    if (cvss.v2_score !== null && cvss.v2_score !== undefined) {
        const color = getScoreColor(cvss.v2_score);
        html += `<div class="cvss-box">
            <h3>CVSS v2.0</h3>
            <div class="cvss-score" style="color:${color}">
                ${cvss.v2_score.toFixed(1)}
            </div>
            <div class="score-bar">
                <div class="score-bar-fill"
                     style="width:${cvss.v2_score * 10}%;
                            background:${color}"></div>
            </div>
            ${cvss.v2_vector
                ? `<div class="cvss-vector">${escapeHTML(cvss.v2_vector)}</div>`
                : ''}
        </div>`;
    }

    if (!html) {
        html = '<p style="color:var(--text-secondary)">' +
               'No CVSS scores available.</p>';
    }
    panel.innerHTML = html;
}

function renderCWEs(cweIds) {
    const section = document.getElementById('cweSection');
    if (!cweIds || cweIds.length === 0) {
        section.innerHTML = '<p style="color:var(--text-secondary)">' +
            'No CWE classification available.</p>';
        return;
    }

    section.innerHTML = cweIds.map(cwe => {
        const num = cwe.replace('CWE-', '');
        return `<span class="cwe-tag"
                      onclick="goToCWE('${escapeHTML(num)}')"
                >${escapeHTML(cwe)}</span>`;
    }).join('');
}

function renderProducts(products) {
    const section = document.getElementById('productsSection');
    if (!products || products.length === 0) {
        section.innerHTML = '<p style="color:var(--text-secondary)">' +
            'No affected product data available.</p>';
        return;
    }

    const seen = new Set();
    const unique = products.filter(p => {
        const key = `${p.vendor}|${p.product}|${p.version}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    }).slice(0, 50);

    let html = '<table class="data-table"><thead><tr>';
    html += '<th>Vendor</th><th>Product</th><th>Version</th>';
    html += '</tr></thead><tbody>';

    unique.forEach(p => {
        html += `<tr>
            <td>${escapeHTML(p.vendor)}</td>
            <td>${escapeHTML(p.product)}</td>
            <td>${escapeHTML(p.version)}</td>
        </tr>`;
    });

    html += '</tbody></table>';
    section.innerHTML = html;
}

function renderReferences(references) {
    const section = document.getElementById('referencesSection');
    if (!references || references.length === 0) {
        section.innerHTML = '<p style="color:var(--text-secondary)">' +
            'No references available.</p>';
        return;
    }

    let html = '<ul class="ref-list">';
    references.forEach(ref => {
        const tags = (ref.tags || []).map(t =>
            `<span class="ref-tag">${escapeHTML(t)}</span>`
        ).join('');
        html += `<li>
            <a href="${escapeHTML(ref.url)}" target="_blank"
               rel="noopener noreferrer">${escapeHTML(ref.url)}</a>
            ${tags}
        </li>`;
    });
    html += '</ul>';
    section.innerHTML = html;
}

function getScoreColor(score) {
    if (score >= 9.0) return 'var(--severity-critical)';
    if (score >= 7.0) return 'var(--severity-high)';
    if (score >= 4.0) return 'var(--severity-medium)';
    return 'var(--severity-low)';
}

// ATT&CK tactic colors
const TACTIC_COLORS = {
    'TA0043': '#8b5cf6', 'TA0042': '#7c3aed', 'TA0001': '#dc2626',
    'TA0002': '#ea580c', 'TA0003': '#d97706', 'TA0004': '#ca8a04',
    'TA0005': '#65a30d', 'TA0006': '#16a34a', 'TA0007': '#0d9488',
    'TA0008': '#0891b2', 'TA0009': '#2563eb', 'TA0011': '#4f46e5',
    'TA0010': '#7c3aed', 'TA0040': '#be185d',
};

async function loadAttackMapping(cveId) {
    const section = document.getElementById('attackSection');
    const summary = document.getElementById('attackSummary');
    const detail = document.getElementById('attackDetail');
    const list = document.getElementById('attackList');
    const toggleBtn = document.getElementById('attackToggleBtn');
    if (!section || !summary) return;

    try {
        const data = await fetchAPI(
            `/api/cve/${encodeURIComponent(cveId)}/attack`
        );

        if (!data.techniques || data.techniques.length === 0) return;

        // Build summary bar with tactic pills and count
        let summaryHtml = '<div class="attack-summary-row">';
        summaryHtml += `<span class="attack-summary-count">${data.techniques.length} technique${data.techniques.length !== 1 ? 's' : ''} mapped via ${data.cwe_sources.length} CWE${data.cwe_sources.length !== 1 ? 's' : ''}</span>`;
        summaryHtml += '<div class="attack-summary-tactics">';
        data.tactics.forEach(t => {
            const color = TACTIC_COLORS[t.id] || '#6b7280';
            summaryHtml += `<span class="attack-tactic-pill" style="background:${color};">${escapeHTML(t.name)}</span>`;
        });
        summaryHtml += '</div></div>';

        // CWE source chips
        if (data.cwe_sources && data.cwe_sources.length > 0) {
            summaryHtml += '<div class="attack-cwe-sources">';
            data.cwe_sources.forEach(cwe => {
                summaryHtml += `<span class="attack-cwe-source-chip" onclick="goToCWE('${escapeHTML(cwe.id)}')">CWE-${escapeHTML(cwe.id)}: ${escapeHTML(cwe.name)}</span>`;
            });
            summaryHtml += '</div>';
        }

        summary.innerHTML = summaryHtml;

        // Build expanded detail view grouped by tactic
        const tacticMap = {};
        data.tactics.forEach(t => {
            tacticMap[t.id] = { ...t, techniques: [] };
        });
        data.techniques.forEach(tech => {
            tech.tactics.forEach(tid => {
                if (tacticMap[tid]) {
                    tacticMap[tid].techniques.push(tech);
                }
            });
        });

        let detailHtml = '<div class="attack-tactics-grid">';
        for (const tactic of data.tactics) {
            const group = tacticMap[tactic.id];
            if (!group || group.techniques.length === 0) continue;
            const color = TACTIC_COLORS[tactic.id] || '#6b7280';

            detailHtml += `<div class="attack-tactic-group">`;
            detailHtml += `<div class="attack-tactic-header" style="border-left: 3px solid ${color};">`;
            detailHtml += `<span class="attack-tactic-name">${escapeHTML(tactic.name)}</span>`;
            detailHtml += `<span class="attack-tactic-id">${escapeHTML(tactic.id)}</span>`;
            detailHtml += `</div>`;
            detailHtml += `<div class="attack-technique-list">`;

            group.techniques.forEach(tech => {
                const sub = tech.is_subtechnique ? ' attack-subtechnique' : '';
                detailHtml += `<a class="attack-technique-card${sub}"
                                  href="${escapeHTML(tech.url)}"
                                  target="_blank" rel="noopener noreferrer"
                                  title="${escapeHTML(tech.description)}">`;
                detailHtml += `<span class="attack-tech-id">${escapeHTML(tech.id)}</span>`;
                detailHtml += `<span class="attack-tech-name">${escapeHTML(tech.name)}</span>`;
                detailHtml += `</a>`;
            });

            detailHtml += `</div></div>`;
        }
        detailHtml += '</div>';

        // CAPEC reference
        if (data.capec_ids && data.capec_ids.length > 0) {
            detailHtml += '<div class="attack-capec-ref">';
            detailHtml += '<span class="attack-capec-label">Mapped via CAPEC:</span> ';
            data.capec_ids.forEach((id, i) => {
                if (i > 0) detailHtml += ', ';
                detailHtml += `<a href="https://capec.mitre.org/data/definitions/${encodeURIComponent(id)}.html"
                                  target="_blank" rel="noopener noreferrer"
                                  class="attack-capec-link">CAPEC-${escapeHTML(id)}</a>`;
            });
            detailHtml += '</div>';
        }

        list.innerHTML = detailHtml;
        section.style.display = '';

        // Highlight the section briefly
        section.classList.add('attack-section-highlight');
        setTimeout(() => section.classList.remove('attack-section-highlight'), 2000);

        // Toggle expand/collapse
        let expanded = false;
        toggleBtn.addEventListener('click', function () {
            expanded = !expanded;
            detail.style.display = expanded ? '' : 'none';
            toggleBtn.classList.toggle('attack-expand-btn-open', expanded);
        });

    } catch (err) {
        console.warn('ATT&CK mapping load failed:', err.message);
    }
}

function showError(message) {
    document.getElementById('loading').style.display = 'none';
    const errorDiv = document.getElementById('errorDiv');
    errorDiv.style.display = 'block';
    errorDiv.innerHTML = `<p>${escapeHTML(message)}</p>
        <p style="margin-top:1rem;">
            <a href="/" style="color:var(--accent-blue);">
                Return to Home
            </a>
        </p>`;
}
