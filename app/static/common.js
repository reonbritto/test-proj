/**
 * Shared utilities for PureSecure CVE Explorer.
 * XSS prevention, fetch wrappers, and UI helpers.
 */

// Prevent XSS by escaping HTML special characters
function escapeHTML(str) {
    if (!str) return '';
    const temp = document.createElement('div');
    temp.textContent = str;
    return temp.innerHTML;
}

// Wrapper around fetch with error handling
async function fetchAPI(url) {
    const response = await fetch(url);
    if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || `API error: ${response.status}`);
    }
    return response.json();
}

// Format ISO date string to readable format
function formatDate(isoString) {
    if (!isoString) return 'N/A';
    const d = new Date(isoString);
    return d.toLocaleDateString('en-GB', {
        year: 'numeric', month: 'short', day: 'numeric'
    });
}

// Get CSS class for severity level
function severityClass(severity) {
    if (!severity) return 'severity-unknown';
    switch (severity.toUpperCase()) {
        case 'CRITICAL': return 'severity-critical';
        case 'HIGH': return 'severity-high';
        case 'MEDIUM': return 'severity-medium';
        case 'LOW': return 'severity-low';
        default: return 'severity-unknown';
    }
}

// Create severity badge HTML
function severityBadge(score, severity) {
    const cls = severityClass(severity);
    const label = severity ? escapeHTML(severity) : 'N/A';
    const scoreText = score !== null && score !== undefined
        ? score.toFixed(1) : '?';
    return `<span class="badge ${cls}">${scoreText} ${label}</span>`;
}

// Get URL parameters
function getParam(name) {
    const params = new URLSearchParams(window.location.search);
    return params.get(name);
}

// Navigate to CVE detail page
function goToCVE(cveId) {
    window.location.href =
        `/cve.html?id=${encodeURIComponent(cveId)}`;
}

// Navigate to CWE detail page
function goToCWE(cweId) {
    window.location.href =
        `/cwe.html?id=${encodeURIComponent(cweId)}`;
}

// Navigate to search page
function goToSearch(query) {
    window.location.href =
        `/search.html?keyword=${encodeURIComponent(query)}`;
}

// Render suggestion dropdown items from API data
function renderSuggestions(data) {
    return data.map(item => {
        const icon = item.type === 'cwe'
            ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`
            : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>`;
        if (item.action) {
            return `<a href="${escapeHTML(item.action)}" class="suggestion-item">${icon}<span>${escapeHTML(item.text)}</span><span class="suggestion-type">${escapeHTML(item.type)}</span></a>`;
        }
        return `<div class="suggestion-item suggestion-tip">${icon}<span>${escapeHTML(item.text)}</span></div>`;
    }).join('');
}

// Create a CVE card element
function createCVECard(cve, index) {
    const card = document.createElement('div');
    card.className = 'cve-card';
    card.style.animationDelay = `${index * 0.03}s`;

    const sevClass = severityClass(cve.severity);
    const badge = cve.cvss_v3 !== null && cve.cvss_v3 !== undefined
        ? severityBadge(cve.cvss_v3, cve.severity)
        : '<span class="badge severity-unknown">N/A</span>';

    card.innerHTML = `
        <div class="cve-card-severity ${sevClass}"></div>
        <div class="cve-card-body">
            <div class="cve-card-title">
                ${escapeHTML(cve.description || 'No description available')}
            </div>
            <div class="cve-card-meta">
                <span class="cve-card-id">${escapeHTML(cve.cve_id)}</span>
                ${badge}
                <span class="cve-card-date">${formatDate(cve.published)}</span>
            </div>
        </div>
    `;

    card.addEventListener('click', () => goToCVE(cve.cve_id));
    return card;
}
