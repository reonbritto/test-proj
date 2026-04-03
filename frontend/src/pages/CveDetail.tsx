import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Calendar, ExternalLink, ChevronDown, ChevronUp, Shield, Package, Link2, Crosshair, Target, Zap, ChevronRight } from 'lucide-react';
import Loading from '../components/Loading';
import SeverityBadge from '../components/SeverityBadge';
import { useApi } from '../hooks/useApi';
import { formatDate, getScoreColor, TACTIC_COLORS } from '../utils/format';
import type { CVEDetail, AttackMapping, Tactic } from '../utils/types';

export default function CveDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [attackExpanded, setAttackExpanded] = useState(false);

  const { data, isLoading, error } = useApi<CVEDetail>(
    ['cve', id!],
    `/api/cve/${id}`,
    { enabled: !!id }
  );

  const { data: attackData } = useApi<AttackMapping>(
    ['cve-attack', id!],
    `/api/cve/${id}/attack`,
    { enabled: !!id }
  );

  if (!id || !/^CVE-\d{4}-\d{4,}$/i.test(id)) {
    return (
      <main className="container detail-page">
        <div className="error-message">
          <p>Invalid CVE ID format. Expected: CVE-YYYY-NNNNN</p>
          <p style={{ marginTop: '1rem' }}>
            <a href="/" style={{ color: 'var(--accent-blue)' }}>Return to Home</a>
          </p>
        </div>
      </main>
    );
  }

  if (isLoading) return <main className="container detail-page"><Loading message="Loading CVE details..." /></main>;

  if (error || !data) {
    return (
      <main className="container detail-page">
        <div className="error-message">
          <p>Failed to load {id}: {(error as Error)?.message || 'Unknown error'}</p>
          <p style={{ marginTop: '1rem' }}>
            <a href="/" style={{ color: 'var(--accent-blue)' }}>Return to Home</a>
          </p>
        </div>
      </main>
    );
  }

  // Unique products
  const seen = new Set<string>();
  const uniqueProducts = (data.affected_products || [])
    .filter((p) => {
      const key = `${p.vendor}|${p.product}|${p.version}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, 50);

  // ATT&CK data processing
  const hasAttack = attackData?.techniques && attackData.techniques.length > 0;
  let tacticMap: Record<string, { tactic: Tactic; techniques: AttackMapping['techniques'] }> = {};
  if (hasAttack) {
    attackData!.tactics.forEach((t) => {
      tacticMap[t.id] = { tactic: t, techniques: [] };
    });
    attackData!.techniques.forEach((tech) => {
      tech.tactics.forEach((tid) => {
        if (tacticMap[tid]) {
          tacticMap[tid].techniques.push(tech);
        }
      });
    });
  }

  return (
    <main className="container detail-page">
      {/* Header */}
      <div className="cwe-detail-header">
        <div>
          <div className="cwe-header-badges">
            <span className="cwe-detail-id">{data.cve_id}</span>
            <SeverityBadge score={data.cvss.v3_score} severity={data.cvss.v3_severity} />
          </div>
          <div style={{ display: 'flex', gap: '1.25rem', color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '0.6rem', alignItems: 'center' }}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
              <Calendar size={14} /> Published: {formatDate(data.published)}
            </span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
              <Calendar size={14} /> Modified: {formatDate(data.modified)}
            </span>
          </div>
        </div>
      </div>

      {/* Description */}
      <div className="detail-card">
        <h2>Description</h2>
        <p className="description">{data.description}</p>
      </div>

      {/* CVSS Scores */}
      <div className="detail-card">
        <h2>CVSS Scores</h2>
        <div style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap' }}>
          {data.cvss.v3_score != null && (
            <div className="cvss-box">
              <h3>CVSS v3.1</h3>
              <div className="cvss-score" style={{ color: getScoreColor(data.cvss.v3_score) }}>
                {data.cvss.v3_score.toFixed(1)}
              </div>
              <div className="score-bar">
                <div
                  className="score-bar-fill"
                  style={{ width: `${data.cvss.v3_score * 10}%`, background: getScoreColor(data.cvss.v3_score) }}
                />
              </div>
              {data.cvss.v3_vector && (
                <div className="cvss-vector">{data.cvss.v3_vector}</div>
              )}
              {data.cvss.v3_severity && (
                <div style={{ marginTop: '0.6rem' }}>
                  <SeverityBadge score={data.cvss.v3_score} severity={data.cvss.v3_severity} />
                </div>
              )}
            </div>
          )}
          {data.cvss.v2_score != null && (
            <div className="cvss-box">
              <h3>CVSS v2.0</h3>
              <div className="cvss-score" style={{ color: getScoreColor(data.cvss.v2_score) }}>
                {data.cvss.v2_score.toFixed(1)}
              </div>
              <div className="score-bar">
                <div
                  className="score-bar-fill"
                  style={{ width: `${data.cvss.v2_score * 10}%`, background: getScoreColor(data.cvss.v2_score) }}
                />
              </div>
              {data.cvss.v2_vector && (
                <div className="cvss-vector">{data.cvss.v2_vector}</div>
              )}
            </div>
          )}
          {data.cvss.v3_score == null && data.cvss.v2_score == null && (
            <p style={{ color: 'var(--text-secondary)' }}>No CVSS scores available.</p>
          )}
        </div>
      </div>

      {/* CWE Classifications */}
      <div className="detail-card">
        <h2><Shield size={18} /> CWE Classification</h2>
        {(!data.cwe_ids || data.cwe_ids.length === 0) ? (
          <p style={{ color: 'var(--text-secondary)' }}>No CWE classification available.</p>
        ) : (
          <div>
            {data.cwe_ids.map((cwe) => {
              const num = cwe.replace('CWE-', '');
              return (
                <span key={cwe} className="cwe-tag" onClick={() => navigate(`/cwe/${num}`)}>
                  {cwe}
                </span>
              );
            })}
          </div>
        )}
      </div>

      {/* Affected Products */}
      <div className="detail-card">
        <h2><Package size={18} /> Affected Products</h2>
        {uniqueProducts.length === 0 ? (
          <p style={{ color: 'var(--text-secondary)' }}>No affected product data available.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr><th>Vendor</th><th>Product</th><th>Version</th></tr>
            </thead>
            <tbody>
              {uniqueProducts.map((p, i) => (
                <tr key={i}>
                  <td>{p.vendor}</td>
                  <td>{p.product}</td>
                  <td>{p.version}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* References */}
      <div className="detail-card">
        <h2><Link2 size={18} /> References</h2>
        {(!data.references || data.references.length === 0) ? (
          <p style={{ color: 'var(--text-secondary)' }}>No references available.</p>
        ) : (
          <ul className="ref-list">
            {data.references.map((ref, i) => (
              <li key={i}>
                <a href={ref.url} target="_blank" rel="noopener noreferrer">
                  <ExternalLink size={12} style={{ marginRight: '0.4rem', opacity: 0.5 }} />
                  {ref.url}
                </a>
                {ref.tags?.map((t, j) => (
                  <span key={j} className="ref-tag">{t}</span>
                ))}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* ATT&CK Mapping */}
      {hasAttack && (
        <div className="detail-card attack-section-highlight">
          <div className="detail-card-header">
            <h2><Crosshair size={18} /> MITRE ATT&CK Mapping</h2>
            <button
              className={`attack-expand-btn ${attackExpanded ? 'attack-expand-btn-open' : ''}`}
              onClick={() => setAttackExpanded(!attackExpanded)}
            >
              {attackExpanded ? <><ChevronUp size={15} /> Collapse</> : <><ChevronDown size={15} /> Expand</>}
            </button>
          </div>

          {/* Visual Summary Cards */}
          <div className="attack-cve-summary">
            <div className="attack-cve-stat">
              <Target size={16} />
              <span className="attack-cve-stat-val">{attackData!.techniques.length}</span>
              <span className="attack-cve-stat-label">technique{attackData!.techniques.length !== 1 ? 's' : ''}</span>
            </div>
            <div className="attack-cve-stat">
              <Zap size={16} />
              <span className="attack-cve-stat-val">{attackData!.tactics.length}</span>
              <span className="attack-cve-stat-label">tactic{attackData!.tactics.length !== 1 ? 's' : ''}</span>
            </div>
            <div className="attack-cve-stat">
              <Shield size={16} />
              <span className="attack-cve-stat-val">{attackData!.cwe_sources.length}</span>
              <span className="attack-cve-stat-label">CWE source{attackData!.cwe_sources.length !== 1 ? 's' : ''}</span>
            </div>
          </div>

          {/* Tactics as colored chips */}
          <div className="attack-summary-tactics">
            {attackData!.tactics.map((t) => (
              <span key={t.id} className="attack-tactic-pill" style={{ background: TACTIC_COLORS[t.id] || '#6b7280' }}>
                {t.name}
              </span>
            ))}
          </div>

          {/* CWE Source chips */}
          {attackData!.cwe_sources.length > 0 && (
            <div className="attack-cwe-sources">
              <span className="attack-sources-label">Mapped via:</span>
              {attackData!.cwe_sources.map((cwe) => (
                <span key={cwe.id} className="attack-cwe-source-chip" onClick={() => navigate(`/cwe/${cwe.id}`)}>
                  <Shield size={12} />
                  CWE-{cwe.id}
                  <span className="source-chip-name">{cwe.name}</span>
                  <ChevronRight size={12} className="source-chip-arrow" />
                </span>
              ))}
            </div>
          )}

          {/* Expanded Detail view */}
          {attackExpanded && (
            <div className="attack-detail-expand">
              <div className="attack-tactics-grid">
                {attackData!.tactics.map((tactic) => {
                  const group = tacticMap[tactic.id];
                  if (!group || group.techniques.length === 0) return null;
                  const color = TACTIC_COLORS[tactic.id] || '#6b7280';

                  return (
                    <div key={tactic.id} className="attack-tactic-group">
                      <div className="attack-tactic-header" style={{ borderLeft: `4px solid ${color}` }}>
                        <div>
                          <span className="attack-tactic-name">{tactic.name}</span>
                          <span className="attack-tactic-id">{tactic.id}</span>
                        </div>
                        <span className="attack-tactic-tech-count">{group.techniques.length} technique{group.techniques.length !== 1 ? 's' : ''}</span>
                      </div>
                      <div className="attack-technique-list">
                        {group.techniques.map((tech) => (
                          <a
                            key={tech.id}
                            className={`attack-technique-card${tech.is_subtechnique ? ' attack-subtechnique' : ''}`}
                            href={tech.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            title={tech.description}
                          >
                            <span className="attack-tech-id">{tech.id}</span>
                            <span className="attack-tech-name">{tech.name}</span>
                            <ExternalLink size={11} className="tech-card-ext" />
                          </a>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>

              {attackData!.capec_ids && attackData!.capec_ids.length > 0 && (
                <div className="attack-capec-ref">
                  <span className="attack-capec-label">CAPEC References:</span>
                  <div className="attack-capec-chips">
                    {attackData!.capec_ids.map((capecId) => (
                      <a
                        key={capecId}
                        href={`https://capec.mitre.org/data/definitions/${capecId}.html`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="attack-capec-chip"
                      >
                        CAPEC-{capecId}
                        <ExternalLink size={10} />
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </main>
  );
}
