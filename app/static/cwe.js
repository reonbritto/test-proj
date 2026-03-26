(function () {
    const cweId = getParam('id');
    if (!cweId) {
        showError('No CWE ID provided. Use ?id=79');
        return;
    }

    if (!/^\d+$/.test(cweId)) {
        showError('Invalid CWE ID format. Expected numeric ID (e.g., 79).');
        return;
    }

    loadCWE(cweId);
})();

async function loadCWE(cweId) {
    const loading = document.getElementById('loading');
    const content = document.getElementById('cweContent');

    try {
        const data = await fetchAPI(
            `/api/cwe/${encodeURIComponent(cweId)}`
        );

        // Header
        const idBadge = document.getElementById('cweIdBadge');
        const nameEl = document.getElementById('cweName');
        if (idBadge) idBadge.textContent = `CWE-${data.id}`;
        if (nameEl) nameEl.textContent = data.name;
        document.title = `CWE-${data.id}: ${data.name} - PureSecure`;

        // Description
        const descEl = document.getElementById('cweDescription');
        if (descEl) descEl.textContent = data.description;

        // MITRE link
        const mitreEl = document.getElementById('mitreLink');
        if (mitreEl) {
            mitreEl.href =
                `https://cwe.mitre.org/data/definitions/${encodeURIComponent(data.id)}.html`;
        }

        // Related weaknesses
        renderRelationships(data.related_weaknesses || []);

        loading.style.display = 'none';
        content.style.display = 'block';

        loadAssociatedCVEs(cweId);
    } catch (err) {
        showError(
            `Failed to load CWE-${escapeHTML(cweId)}: ` +
            escapeHTML(err.message)
        );
    }
}

function renderRelationships(relationships) {
    const section = document.getElementById('relationshipsSection');
    const list = document.getElementById('relationshipsList');

    if (!section || !list) return;

    if (!relationships || relationships.length === 0) {
        section.style.display = 'none';
        return;
    }

    // Group by nature
    const groups = {};
    relationships.forEach(rel => {
        const nature = rel.nature || 'Related';
        if (!groups[nature]) groups[nature] = [];
        groups[nature].push(rel.cwe_id);
    });

    let html = '';
    const labels = {
        'ChildOf': 'Parent Weakness',
        'ParentOf': 'Child Weakness',
        'PeerOf': 'Peer Weakness',
        'CanPrecede': 'Can Lead To',
        'CanFollow': 'Can Follow',
        'StartsWith': 'Starts With',
        'Requires': 'Requires'
    };

    for (const [nature, ids] of Object.entries(groups)) {
        const label = labels[nature] || nature;
        html += `<div class="rel-group">`;
        html += `<span class="rel-group-label">${escapeHTML(label)}</span>`;
        html += `<div class="rel-group-tags">`;
        ids.forEach(id => {
            html += `<a class="rel-chip" onclick="goToCWE('${escapeHTML(id)}')">CWE-${escapeHTML(id)}</a>`;
        });
        html += `</div></div>`;
    }

    section.style.display = 'block';
    list.innerHTML = html;
}

async function loadAssociatedCVEs(cweId) {
    const loading2 = document.getElementById('loading2');
    const cvesList = document.getElementById('cvesList');
    const cveCount = document.getElementById('cveCount');

    try {
        const data = await fetchAPI(
            `/api/cwe/${encodeURIComponent(cweId)}/cves`
        );
        loading2.style.display = 'none';

        if (data.length === 0) {
            cveCount.textContent = '0 CVEs';
            cvesList.innerHTML =
                '<p style="color:var(--text-secondary);padding:0.5rem 0;">' +
                'No CVEs found for this CWE in the NVD database.</p>';
            return;
        }

        cveCount.textContent = `${data.length} CVEs`;

        let html = '<table class="data-table"><thead><tr>';
        html += '<th>CVE ID</th><th>Severity</th><th>Score</th>';
        html += '<th>Published</th><th>Description</th>';
        html += '</tr></thead><tbody>';

        data.forEach(cve => {
            const badge = cve.severity
                ? severityBadge(cve.cvss_v3, cve.severity)
                : '<span class="badge severity-unknown">N/A</span>';
            const score = cve.cvss_v3 !== null && cve.cvss_v3 !== undefined
                ? cve.cvss_v3.toFixed(1) : 'N/A';

            html += `<tr class="card-clickable"
                         onclick="goToCVE('${escapeHTML(cve.cve_id)}')">
                <td><strong class="cve-link">
                    ${escapeHTML(cve.cve_id)}</strong></td>
                <td>${badge}</td>
                <td>${score}</td>
                <td>${formatDate(cve.published)}</td>
                <td class="desc-cell">
                    ${escapeHTML(cve.description)}</td>
            </tr>`;
        });

        html += '</tbody></table>';
        cvesList.innerHTML = html;
    } catch (err) {
        loading2.style.display = 'none';
        cvesList.innerHTML =
            `<p class="error-message">Failed to load CVEs: ` +
            `${escapeHTML(err.message)}</p>`;
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
