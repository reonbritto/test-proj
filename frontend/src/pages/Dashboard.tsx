import { Link } from 'react-router-dom';
import { Shield, ArrowRight, Zap, Eye, Lock } from 'lucide-react';
import SearchInput from '../components/SearchInput';
import CWECard from '../components/CWECard';
import Loading from '../components/Loading';
import { useApi } from '../hooks/useApi';
import type { CWESummary } from '../utils/types';

export default function Dashboard() {
  const { data: cwes, isLoading, error } = useApi<CWESummary[]>(
    'featured-cwes',
    '/api/cwe/featured'
  );

  return (
    <>
      <section className="hero-banner">
        <div className="hero-inner">
          <div className="hero-brand">
            <Shield size={28} strokeWidth={2.2} />
            PureSecure
          </div>

          <div className="hero-tagline">
            <span className="tag-collect"><Zap size={14} /> Collect</span>
            <span className="tag-display"><Eye size={14} /> Display</span>
            <span className="tag-secure"><Lock size={14} /> Secure</span>
          </div>

          <div className="hero-title-pill">The Cyber Security Weakness Database</div>

          <div className="hero-search">
            <SearchInput />
          </div>

          <div className="quick-links">
            <span className="quick-label">Popular:</span>
            <Link to="/cwe/79" className="quick-chip">XSS</Link>
            <Link to="/cwe/89" className="quick-chip">SQL Injection</Link>
            <Link to="/cwe/787" className="quick-chip">Out-of-bounds Write</Link>
            <Link to="/cwe/416" className="quick-chip">Use After Free</Link>
            <Link to="/cwe/78" className="quick-chip">OS Command Injection</Link>
          </div>
        </div>
      </section>

      <main className="container">
        <section>
          <div className="section-header">
            <h2 className="section-title">Common Weaknesses</h2>
            <Link to="/search" className="view-all">
              Explore More <ArrowRight size={16} />
            </Link>
          </div>

          {isLoading && <Loading message="Loading CWE data..." />}

          {error && (
            <div className="empty-state">
              <p>Could not load CWE data.</p>
              <p className="subtext">{(error as Error).message}</p>
            </div>
          )}

          {cwes && cwes.length === 0 && (
            <div className="empty-state">
              <p>No CWE data loaded yet.</p>
              <p className="subtext">
                Try searching for a weakness like{' '}
                <Link to="/cwe/79" style={{ color: 'var(--green-dark)' }}>
                  CWE-79 (XSS)
                </Link>{' '}
                to start exploring.
              </p>
            </div>
          )}

          <div className="cwe-feed">
            {cwes?.map((cwe, index) => (
              <CWECard key={cwe.id} cwe={cwe} index={index} />
            ))}
          </div>
        </section>
      </main>
    </>
  );
}
