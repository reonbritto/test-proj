document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('searchInput');
    const searchBtn = document.getElementById('searchBtn');
    const suggestionsDiv = document.getElementById('suggestions');

    let debounceTimer = null;

    // Search handlers
    searchBtn.addEventListener('click', handleSearch);
    searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            suggestionsDiv.classList.remove('active');
            handleSearch();
        }
    });

    // Live suggestions as user types
    searchInput.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        const q = searchInput.value.trim();
        if (q.length < 2) {
            suggestionsDiv.classList.remove('active');
            return;
        }
        debounceTimer = setTimeout(() => fetchSuggestions(q), 250);
    });

    // Close suggestions on outside click
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.hero-search')) {
            suggestionsDiv.classList.remove('active');
        }
    });

    function handleSearch() {
        const q = searchInput.value.trim();
        if (!q) return;
        if (/^CVE-\d{4}-\d{4,}$/i.test(q)) {
            goToCVE(q.toUpperCase());
        } else {
            goToSearch(q);
        }
    }

    async function fetchSuggestions(q) {
        try {
            const data = await fetchAPI(
                `/api/cve/suggestions?q=${encodeURIComponent(q)}`
            );
            if (data.length === 0) {
                suggestionsDiv.classList.remove('active');
                return;
            }
            suggestionsDiv.innerHTML = renderSuggestions(data);
            suggestionsDiv.classList.add('active');
        } catch (err) {
            suggestionsDiv.classList.remove('active');
        }
    }

    // Load page data
    loadLatestCVEs();
});

async function loadLatestCVEs() {
    const container = document.getElementById('latestCves');
    const loading = document.getElementById('latestLoading');

    try {
        const data = await fetchAPI('/api/cve/latest?limit=20');
        loading.style.display = 'none';

        if (data.length === 0) {
            container.innerHTML = `<div class="empty-state">
                <p>No CVE data loaded yet.</p>
                <p class="subtext">Try searching for a specific CVE like
                <a href="/cve.html?id=CVE-2021-44228"
                   style="color:var(--green-dark)">CVE-2021-44228</a>
                to start populating the database.</p>
            </div>`;
            return;
        }

        data.forEach((cve, index) => {
            container.appendChild(createCVECard(cve, index));
        });
    } catch (err) {
        loading.style.display = 'none';
        container.innerHTML = `<div class="empty-state">
            <p>Could not load latest CVEs.</p>
            <p class="subtext">${escapeHTML(err.message)}</p>
        </div>`;
    }
}
