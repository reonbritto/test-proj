import { useState, useEffect, useCallback } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { AlertTriangle, AlertCircle, Info, ShieldAlert, Lock, KeyRound } from 'lucide-react';
import SearchInput from '../components/SearchInput';
import CWECard from '../components/CWECard';
import Loading from '../components/Loading';
import { fetchAPI } from '../utils/api';
import type { CWESummary } from '../utils/types';

export default function Search() {
  const [searchParams, setSearchParams] = useSearchParams();
  const keyword = searchParams.get('keyword') || '';
  const [results, setResults] = useState<CWESummary[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const performSearch = useCallback(async (query: string) => {
    if (!query) return;

    // Strip CWE- prefix for ID search
    let q = query;
    const cweMatch = query.match(/^CWE-?(\d+)$/i);
    if (cweMatch) {
      q = cweMatch[1];
    }

    setLoading(true);
    setError(null);
    setResults(null);

    try {
      const data = await fetchAPI<CWESummary[]>(
        `/api/cwe?limit=50&query=${encodeURIComponent(q)}`
      );
      setResults(data);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  // Search on mount if keyword in URL
  useEffect(() => {
    if (keyword) {
      performSearch(keyword);
    }
  }, [keyword, performSearch]);

  const handleSearch = (query: string) => {
    setSearchParams({ keyword: query });
  };

  return (
    <main className="container">
      <div className="search-page-header">
        <h1>Search Weaknesses</h1>
        <p>Browse the CWE catalogue by name, ID, or keyword to find common software weaknesses.</p>
      </div>

      <div className="search-wrapper">
        <SearchInput
          initialValue={keyword}
          onSearch={handleSearch}
          placeholder="e.g. CWE-79, sql injection, buffer overflow..."
        />
      </div>

      {/* Recommendations before search */}
      {!keyword && !results && (
        <div className="recommendations">
          <h3>Browse by Category</h3>
          <div className="rec-grid">
            <Link to="/cwe/20" className="rec-card">
              <div className="rec-icon critical"><AlertTriangle size={18} /></div>
              <div>
                <strong>Input Validation</strong>
                <p>CWE-20: Improper input handling</p>
              </div>
            </Link>
            <Link to="/cwe/89" className="rec-card">
              <div className="rec-icon high"><AlertCircle size={18} /></div>
              <div>
                <strong>SQL Injection</strong>
                <p>CWE-89: Database injection flaws</p>
              </div>
            </Link>
            <Link to="/cwe/79" className="rec-card">
              <div className="rec-icon medium"><Info size={18} /></div>
              <div>
                <strong>Cross-Site Scripting</strong>
                <p>CWE-79: XSS attack vectors</p>
              </div>
            </Link>
            <Link to="/cwe/287" className="rec-card">
              <div className="rec-icon high"><KeyRound size={18} /></div>
              <div>
                <strong>Authentication</strong>
                <p>CWE-287: Improper authentication</p>
              </div>
            </Link>
            <Link to="/cwe/119" className="rec-card">
              <div className="rec-icon medium"><ShieldAlert size={18} /></div>
              <div>
                <strong>Buffer Overflow</strong>
                <p>CWE-119: Memory boundary errors</p>
              </div>
            </Link>
            <Link to="/cwe/284" className="rec-card">
              <div className="rec-icon critical"><Lock size={18} /></div>
              <div>
                <strong>Access Control</strong>
                <p>CWE-284: Improper access control</p>
              </div>
            </Link>
          </div>
        </div>
      )}

      {loading && <Loading message="Searching CWE database..." />}

      {error && (
        <div className="empty-state">
          <p>Search failed: {error}</p>
          <p className="subtext">Please try again.</p>
        </div>
      )}

      {results && (
        <>
          <div className="results-info">
            <span>Showing {results.length} results</span>
          </div>
          {results.length === 0 ? (
            <div className="empty-state">
              <p>No weaknesses found matching your criteria.</p>
              <p className="subtext">Try different keywords or browse the categories above.</p>
            </div>
          ) : (
            <div className="cwe-feed">
              {results.map((cwe, index) => (
                <CWECard key={cwe.id} cwe={cwe} index={index} />
              ))}
            </div>
          )}
        </>
      )}
    </main>
  );
}
