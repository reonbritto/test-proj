(function () {
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
        const cweMatch = q.match(/^(?:CWE-?)?(\d+)$/i);
        if (cweMatch) {
            goToCWE(cweMatch[1]);
        } else {
            goToSearch(q);
        }
    }

    async function fetchSuggestions(q) {
        try {
            const data = await fetchAPI(
                `/api/cwe/suggestions?q=${encodeURIComponent(q)}`
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

    // Load common CWEs for the homepage grid
    loadCommonCWEs();

    async function loadCommonCWEs() {
        const container = document.getElementById('cweGrid');
        const loading = document.getElementById('cweLoading');

        try {
            const data = await fetchAPI('/api/cwe/featured');
            loading.style.display = 'none';

            if (data.length === 0) {
                container.innerHTML = `<div class="empty-state">
                    <p>No CWE data loaded yet.</p>
                    <p class="subtext">Try searching for a weakness like
                    <a href="/cwe.html?id=79"
                       style="color:var(--green-dark)">CWE-79 (XSS)</a>
                    to start exploring.</p>
                </div>`;
                return;
            }

            data.forEach((cwe, index) => {
                container.appendChild(createCWECard(cwe, index));
            });
        } catch (err) {
            loading.style.display = 'none';
            container.innerHTML = `<div class="empty-state">
                <p>Could not load CWE data.</p>
                <p class="subtext">${escapeHTML(err.message)}</p>
            </div>`;
        }
    }
})();
