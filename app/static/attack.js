// MITRE ATT&CK Matrix Page

const TACTIC_COLORS = {
    'TA0043': '#8b5cf6',
    'TA0042': '#7c3aed',
    'TA0001': '#dc2626',
    'TA0002': '#ea580c',
    'TA0003': '#d97706',
    'TA0004': '#ca8a04',
    'TA0005': '#65a30d',
    'TA0006': '#16a34a',
    'TA0007': '#0d9488',
    'TA0008': '#0891b2',
    'TA0009': '#2563eb',
    'TA0011': '#4f46e5',
    'TA0010': '#7c3aed',
    'TA0040': '#be185d',
};

const TACTIC_ORDER = [
    'TA0043', 'TA0042', 'TA0001', 'TA0002', 'TA0003',
    'TA0004', 'TA0005', 'TA0006', 'TA0007', 'TA0008',
    'TA0009', 'TA0011', 'TA0010', 'TA0040',
];

let allTactics = [];
let allTechniques = [];
let cweMap = {};          // technique_id → [{id, name}, ...]
let showMappedOnly = false;

(async function () {
    await loadMatrix();
})();

async function loadMatrix() {
    const loading = document.getElementById('loading');
    const content = document.getElementById('matrixContent');

    try {
        const [tactics, techniques, cweMapData] = await Promise.all([
            fetchAPI('/api/attack/tactics'),
            fetchAPI('/api/attack/techniques'),
            fetchAPI('/api/attack/cwe-map'),
        ]);

        allTactics = tactics;
        allTechniques = techniques;
        cweMap = cweMapData || {};

        // Update stats
        const mappedCount = Object.keys(cweMap).length;
        const totalCWEs = new Set();
        Object.values(cweMap).forEach(cwes => {
            cwes.forEach(c => totalCWEs.add(c.id));
        });
        document.getElementById('statsTotal').textContent = techniques.length;
        document.getElementById('statsMapped').textContent = mappedCount;
        document.getElementById('statsCWEs').textContent = totalCWEs.size;

        renderMatrix(tactics, techniques);

        loading.style.display = 'none';
        content.style.display = '';

        // Search handler
        document.getElementById('attackSearch').addEventListener('input', function () {
            filterMatrix(this.value.toLowerCase().trim());
        });

        // Toggle mapped-only filter
        document.getElementById('mappedOnlyToggle').addEventListener('change', function () {
            showMappedOnly = this.checked;
            filterMatrix(document.getElementById('attackSearch').value.toLowerCase().trim());
        });

        // Close panel
        document.getElementById('closePanelBtn').addEventListener('click', function () {
            document.getElementById('techniquePanel').style.display = 'none';
            // Remove active highlight
            document.querySelectorAll('.attack-matrix-tech-cell.active').forEach(
                el => el.classList.remove('active')
            );
        });

    } catch (err) {
        loading.style.display = 'none';
        const errorDiv = document.getElementById('errorDiv');
        errorDiv.style.display = 'block';
        errorDiv.innerHTML = `<p>Failed to load ATT&CK data: ${escapeHTML(err.message)}</p>
            <p style="margin-top:1rem;">
                <a href="/" style="color:var(--accent-blue);">Return to Home</a>
            </p>`;
    }
}

function renderMatrix(tactics, techniques) {
    const matrix = document.getElementById('attackMatrix');

    const sortedTactics = [...tactics].sort((a, b) => {
        const ai = TACTIC_ORDER.indexOf(a.id);
        const bi = TACTIC_ORDER.indexOf(b.id);
        return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
    });

    let html = '';

    sortedTactics.forEach(tactic => {
        const color = TACTIC_COLORS[tactic.id] || '#6b7280';
        const tacticTechs = techniques.filter(t =>
            t.tactics.includes(tactic.id)
        ).sort((a, b) => {
            // Sort mapped techniques first, then alphabetically
            const aMapped = cweMap[a.id] ? 1 : 0;
            const bMapped = cweMap[b.id] ? 1 : 0;
            if (bMapped !== aMapped) return bMapped - aMapped;
            return a.name.localeCompare(b.name);
        });

        const mappedInTactic = tacticTechs.filter(t => cweMap[t.id]).length;

        html += `<div class="attack-matrix-column" data-tactic="${escapeHTML(tactic.id)}">`;
        html += `<div class="attack-matrix-tactic-header" style="background: ${color};">`;
        html += `<span class="attack-matrix-tactic-name">${escapeHTML(tactic.name)}</span>`;
        html += `<span class="attack-matrix-tactic-count">${tacticTechs.length} techniques`;
        if (mappedInTactic > 0) {
            html += ` &middot; ${mappedInTactic} mapped`;
        }
        html += `</span>`;
        html += `</div>`;
        html += `<div class="attack-matrix-techniques">`;

        tacticTechs.forEach(tech => {
            const cwes = cweMap[tech.id];
            const hasCWE = cwes && cwes.length > 0;
            const mappedClass = hasCWE ? ' has-cwe-mapping' : '';
            const cweCount = hasCWE ? cwes.length : 0;

            html += `<div class="attack-matrix-tech-cell${mappedClass}"
                          data-tech-id="${escapeHTML(tech.id)}"
                          data-tech-name="${escapeHTML(tech.name.toLowerCase())}"
                          data-has-cwe="${hasCWE ? '1' : '0'}"
                          onclick="showTechniqueDetail('${escapeHTML(tech.id)}', this)"
                          title="${escapeHTML(tech.id)}: ${escapeHTML(tech.name)}${hasCWE ? ' — ' + cweCount + ' CWE mapping(s)' : ''}">`;
            html += `<div class="attack-cell-top">`;
            html += `<span class="attack-matrix-tech-id">${escapeHTML(tech.id)}</span>`;
            if (hasCWE) {
                html += `<span class="attack-cwe-count-dot" title="${cweCount} mapped CWEs">${cweCount}</span>`;
            }
            html += `</div>`;
            html += `<span class="attack-matrix-tech-name">${escapeHTML(tech.name)}</span>`;
            html += `</div>`;
        });

        html += `</div></div>`;
    });

    matrix.innerHTML = html;
}

function filterMatrix(query) {
    const columns = document.querySelectorAll('.attack-matrix-column');
    columns.forEach(col => {
        const cells = col.querySelectorAll('.attack-matrix-tech-cell');
        let visibleCount = 0;
        cells.forEach(cell => {
            const id = (cell.dataset.techId || '').toLowerCase();
            const name = cell.dataset.techName || '';
            const hasCwe = cell.dataset.hasCwe === '1';
            const textMatch = !query || id.includes(query) || name.includes(query);
            const mappedMatch = !showMappedOnly || hasCwe;
            const show = textMatch && mappedMatch;
            cell.style.display = show ? '' : 'none';
            if (show) visibleCount++;
        });
        col.style.display = visibleCount === 0 && (query || showMappedOnly) ? 'none' : '';
    });
}

async function showTechniqueDetail(techId, cellEl) {
    // Highlight active cell
    document.querySelectorAll('.attack-matrix-tech-cell.active').forEach(
        el => el.classList.remove('active')
    );
    if (cellEl) cellEl.classList.add('active');

    const panel = document.getElementById('techniquePanel');
    const techIdEl = document.getElementById('techId');
    const techNameEl = document.getElementById('techName');
    const techDescEl = document.getElementById('techDesc');
    const subtechSection = document.getElementById('techSubtechniques');
    const subtechList = document.getElementById('subtechList');
    const cweSection = document.getElementById('techCWEs');
    const cweList = document.getElementById('cweList');
    const mitreLink = document.getElementById('techMitreLink');

    panel.style.display = '';
    techIdEl.textContent = techId;
    techNameEl.textContent = 'Loading...';
    techDescEl.textContent = '';
    subtechSection.style.display = 'none';
    cweSection.style.display = 'none';

    try {
        const data = await fetchAPI(
            `/api/attack/technique/${encodeURIComponent(techId)}`
        );

        const tech = data.technique;
        techIdEl.textContent = tech.id;
        techNameEl.textContent = tech.name;
        techDescEl.textContent = tech.description;
        mitreLink.href = tech.url || `https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}/`;

        // Tactics pills
        const tacticPills = document.getElementById('techTactics');
        if (tacticPills && tech.tactics && tech.tactics.length > 0) {
            let pillsHtml = '';
            tech.tactics.forEach(tid => {
                const tactic = allTactics.find(t => t.id === tid);
                if (tactic) {
                    const color = TACTIC_COLORS[tid] || '#6b7280';
                    pillsHtml += `<span class="attack-tactic-pill" style="background:${color};">${escapeHTML(tactic.name)}</span>`;
                }
            });
            tacticPills.innerHTML = pillsHtml;
        }

        // Sub-techniques
        if (data.subtechniques && data.subtechniques.length > 0) {
            let subHtml = '';
            data.subtechniques.forEach(sub => {
                const subHasCwe = cweMap[sub.id] && cweMap[sub.id].length > 0;
                subHtml += `<a class="attack-sub-chip${subHasCwe ? ' has-cwe-mapping' : ''}"
                               href="${escapeHTML(sub.url)}"
                               target="_blank" rel="noopener noreferrer">`;
                subHtml += `<span class="attack-sub-id">${escapeHTML(sub.id)}</span> `;
                subHtml += `${escapeHTML(sub.name)}`;
                if (subHasCwe) {
                    subHtml += ` <span class="attack-cwe-count-dot">${cweMap[sub.id].length}</span>`;
                }
                subHtml += `</a>`;
            });
            subtechList.innerHTML = subHtml;
            subtechSection.style.display = '';
        }

        // Mapped CWEs
        if (data.mapped_cwes && data.mapped_cwes.length > 0) {
            let cweHtml = '';
            data.mapped_cwes.forEach(cwe => {
                cweHtml += `<a class="attack-cwe-chip" onclick="goToCWE('${escapeHTML(cwe.id)}')">`;
                cweHtml += `<span class="attack-cwe-chip-id">CWE-${escapeHTML(cwe.id)}</span>`;
                cweHtml += `<span class="attack-cwe-chip-name">${escapeHTML(cwe.name)}</span>`;
                cweHtml += `</a>`;
            });
            cweList.innerHTML = cweHtml;
            cweSection.style.display = '';
        }

        panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    } catch (err) {
        techNameEl.textContent = 'Error loading technique';
        techDescEl.textContent = err.message;
    }
}
