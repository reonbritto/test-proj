(function () {
    const searchInput = document.getElementById('searchInput');
    const searchBtn = document.getElementById('searchBtn');
    const resultsDiv = document.getElementById('results');
    const loadingDiv = document.getElementById('loading');
    const paginationDiv = document.getElementById('pagination');
    const recommendationsDiv = document.getElementById('recommendations');
    const resultsHeader = document.getElementById('resultsHeader');
    const suggestionsDiv = document.getElementById('suggestions');

    let currentOffset = 0;
    const PAGE_SIZE = 50;
    let debounceTimer = null;

    // Pre-fill from URL params
    const urlKeyword = getParam('keyword');
    if (urlKeyword) {
        searchInput.value = urlKeyword;
        performSearch();
    }

    searchBtn.addEventListener('click', () => {
        currentOffset = 0;
        performSearch();
    });

    searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            currentOffset = 0;
            suggestionsDiv.classList.remove('active');
            performSearch();
        }
    });

    // Live suggestions
    searchInput.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        const q = searchInput.value.trim();
        if (q.length < 2) {
            suggestionsDiv.classList.remove('active');
            return;
        }
        debounceTimer = setTimeout(() => fetchSuggestions(q), 250);
    });

    document.addEventListener('click', (e) => {
        if (!e.target.closest('.search-wrapper')) {
            suggestionsDiv.classList.remove('active');
        }
    });

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

    async function performSearch() {
        const keyword = searchInput.value.trim();

        if (!keyword) return;

        // Clean up query: strip "CWE-" prefix for ID-based search
        let query = keyword;
        const cweMatch = keyword.match(/^CWE-?(\d+)$/i);
        if (cweMatch) {
            query = cweMatch[1];
        }

        recommendationsDiv.style.display = 'none';
        loadingDiv.classList.remove('hidden');
        resultsDiv.innerHTML = '';
        paginationDiv.innerHTML = '';
        resultsHeader.style.display = 'none';

        try {
            const url = `/api/cwe?limit=${PAGE_SIZE}` +
                        `&query=${encodeURIComponent(query)}`;

            const data = await fetchAPI(url);
            displayResults(data);
        } catch (err) {
            resultsDiv.innerHTML = `<div class="empty-state">
                <p>Search failed: ${escapeHTML(err.message)}</p>
                <p class="subtext">Please try again.</p>
            </div>`;
        } finally {
            loadingDiv.classList.add('hidden');
        }
    }

    function displayResults(data) {
        if (data.length === 0) {
            resultsDiv.innerHTML = `<div class="empty-state">
                <p>No weaknesses found matching your criteria.</p>
                <p class="subtext">Try different keywords or browse
                the categories above.</p>
            </div>`;
            return;
        }

        resultsHeader.style.display = 'block';
        document.getElementById('resultsCount').textContent =
            `Showing ${data.length} results`;

        data.forEach((cwe, index) => {
            resultsDiv.appendChild(createCWECard(cwe, index));
        });
    }
})();
