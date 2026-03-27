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

        // Abstraction badge
        const abstractionTooltips = {
            'Pillar': 'Pillar: The highest-level weakness grouping. Too abstract to map to a specific real-world vulnerability.',
            'Class': 'Class: A broadly described weakness, typically language- and technology-independent.',
            'Base': 'Base: A more specific weakness that is still mostly independent of any particular language or technology.',
            'Variant': 'Variant: A weakness tied to a specific language, technology, or context.',
            'Compound': 'Compound: A combination of two or more weaknesses that work together.'
        };
        const statusTooltips = {
            'Stable': 'Stable: This CWE entry has been thoroughly reviewed and is considered mature.',
            'Incomplete': 'Incomplete: This entry has significant gaps and is still being developed.',
            'Draft': 'Draft: This entry is a preliminary version that has not yet been fully reviewed.',
            'Deprecated': 'Deprecated: This entry is no longer recommended for use and may be merged or removed.'
        };

        if (data.abstraction) {
            const badge = document.getElementById('abstractionBadge');
            if (badge) {
                badge.textContent = 'Abstraction: ' + data.abstraction;
                badge.title = abstractionTooltips[data.abstraction] || data.abstraction;
                badge.className = 'cwe-abstraction-badge abstraction-' +
                    data.abstraction.toLowerCase();
                badge.style.display = '';
            }
        }

        // Status badge
        if (data.status) {
            const badge = document.getElementById('statusBadge');
            if (badge) {
                badge.textContent = 'Status: ' + data.status;
                badge.title = statusTooltips[data.status] || data.status;
                badge.className = 'cwe-status-badge status-' +
                    data.status.toLowerCase();
                badge.style.display = '';
            }
        }

        // Description
        const descEl = document.getElementById('cweDescription');
        if (descEl) descEl.textContent = data.description;

        // Extended description
        if (data.extended_description) {
            const extDiv = document.getElementById('extendedDescription');
            const extText = document.getElementById('extDescText');
            if (extDiv && extText) {
                extText.textContent = data.extended_description;
                extDiv.style.display = '';
            }
        }

        // MITRE link
        const mitreEl = document.getElementById('mitreLink');
        if (mitreEl) {
            mitreEl.href =
                `https://cwe.mitre.org/data/definitions/${encodeURIComponent(data.id)}.html`;
        }

        // Applicable platforms
        renderPlatforms(data.applicable_platforms || []);

        // Common consequences
        renderConsequences(data.common_consequences || []);

        // Potential mitigations
        renderMitigations(data.potential_mitigations || []);

        // Detection methods
        renderDetections(data.detection_methods || []);

        // Affected resources
        renderResources(data.affected_resources || []);

        // Taxonomy mappings
        renderTaxonomy(data.taxonomy_mappings || []);

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

function renderPlatforms(platforms) {
    const section = document.getElementById('platformsSection');
    const list = document.getElementById('platformsList');
    if (!section || !list || !platforms.length) return;

    let html = '';
    platforms.forEach(p => {
        const icon = p.type === 'Language' ? 'lang' : 'tech';
        html += `<span class="platform-tag platform-${icon}">` +
            `${escapeHTML(p.name)}</span>`;
    });

    list.innerHTML = html;
    section.style.display = '';
}

function renderConsequences(consequences) {
    const section = document.getElementById('consequencesSection');
    const list = document.getElementById('consequencesList');
    if (!section || !list || !consequences.length) return;

    let html = '<table class="consequences-table"><thead><tr>' +
        '<th>Scope</th><th>Impact</th><th>Likelihood</th>' +
        '</tr></thead><tbody>';

    consequences.forEach(c => {
        const likelihood = c.likelihood || '-';
        const likelihoodClass = c.likelihood
            ? 'likelihood-' + c.likelihood.toLowerCase() : '';
        html += `<tr>
            <td><span class="scope-tag">${escapeHTML(c.scope)}</span></td>
            <td>${escapeHTML(c.impact)}</td>
            <td><span class="likelihood-val ${likelihoodClass}">${escapeHTML(likelihood)}</span></td>
        </tr>`;
    });

    html += '</tbody></table>';
    list.innerHTML = html;
    section.style.display = '';
}

function renderMitigations(mitigations) {
    const section = document.getElementById('mitigationsSection');
    const list = document.getElementById('mitigationsList');
    if (!section || !list || !mitigations.length) return;

    let html = '';
    mitigations.forEach(m => {
        html += `<div class="mitigation-item">
            <div class="mitigation-header">
                <span class="phase-badge">${escapeHTML(m.phase)}</span>`;
        if (m.effectiveness) {
            html += `<span class="effectiveness-badge effectiveness-${m.effectiveness.toLowerCase().replace(/\s+/g, '-')}">` +
                `${escapeHTML(m.effectiveness)}</span>`;
        }
        html += `</div>
            <p class="mitigation-desc">${escapeHTML(m.description)}</p>
        </div>`;
    });

    list.innerHTML = html;
    section.style.display = '';
}

function renderDetections(detections) {
    const section = document.getElementById('detectionsSection');
    const list = document.getElementById('detectionsList');
    if (!section || !list || !detections.length) return;

    let html = '';
    detections.forEach(d => {
        html += `<div class="detection-item">
            <div class="detection-header">
                <span class="method-badge">${escapeHTML(d.method)}</span>`;
        if (d.effectiveness) {
            html += `<span class="effectiveness-badge effectiveness-${d.effectiveness.toLowerCase().replace(/\s+/g, '-')}">` +
                `${escapeHTML(d.effectiveness)}</span>`;
        }
        html += `</div>
            <p class="detection-desc">${escapeHTML(d.description)}</p>
        </div>`;
    });

    list.innerHTML = html;
    section.style.display = '';
}

function renderResources(resources) {
    const section = document.getElementById('resourcesSection');
    const list = document.getElementById('resourcesList');
    if (!section || !list || !resources.length) return;

    let html = '';
    resources.forEach(r => {
        html += `<span class="resource-tag">${escapeHTML(r)}</span>`;
    });

    list.innerHTML = html;
    section.style.display = '';
}

function renderTaxonomy(mappings) {
    const section = document.getElementById('taxonomySection');
    const list = document.getElementById('taxonomyList');
    if (!section || !list || !mappings.length) return;

    let html = '<table class="taxonomy-table"><thead><tr>' +
        '<th>Taxonomy</th><th>ID</th><th>Entry Name</th>' +
        '</tr></thead><tbody>';

    mappings.forEach(m => {
        html += `<tr>
            <td><span class="taxonomy-name">${escapeHTML(m.taxonomy)}</span></td>
            <td>${escapeHTML(m.entry_id || '-')}</td>
            <td>${escapeHTML(m.entry_name || '-')}</td>
        </tr>`;
    });

    html += '</tbody></table>';
    list.innerHTML = html;
    section.style.display = '';
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
