import { useParams, useNavigate } from 'react-router-dom';
import { ExternalLink, Shield, AlertTriangle, Wrench, ScanSearch, Cpu, GitBranch, Bug } from 'lucide-react';
import Loading from '../components/Loading';
import SeverityBadge from '../components/SeverityBadge';
import { useApi } from '../hooks/useApi';
import { formatDate } from '../utils/format';
import type { CWEDetail, CVESummary } from '../utils/types';

export default function CweDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const { data, isLoading, error } = useApi<CWEDetail>(
    ['cwe', id!],
    `/api/cwe/${id}`,
    { enabled: !!id }
  );

  const { data: cves, isLoading: cvesLoading } = useApi<CVESummary[]>(
    ['cwe-cves', id!],
    `/api/cwe/${id}/cves`,
    { enabled: !!id }
  );

  if (!id || !/^\d+$/.test(id)) {
    return (
      <main className="container detail-page">
        <div className="error-message">
          <p>Invalid CWE ID format. Expected numeric ID (e.g., 79).</p>
          <p style={{ marginTop: '1rem' }}>
            <a href="/" style={{ color: 'var(--accent-blue)' }}>Return to Home</a>
          </p>
        </div>
      </main>
    );
  }

  if (isLoading) return <main className="container detail-page"><Loading message="Loading CWE details..." /></main>;

  if (error) {
    return (
      <main className="container detail-page">
        <div className="error-message">
          <p>Failed to load CWE-{id}: {(error as Error).message}</p>
          <p style={{ marginTop: '1rem' }}>
            <a href="/" style={{ color: 'var(--accent-blue)' }}>Return to Home</a>
          </p>
        </div>
      </main>
    );
  }

  if (!data) return null;

  const abstractionTooltips: Record<string, string> = {
    Pillar: 'Pillar: The highest-level weakness grouping.',
    Class: 'Class: A broadly described weakness.',
    Base: 'Base: A more specific weakness.',
    Variant: 'Variant: A weakness tied to a specific language/technology.',
    Compound: 'Compound: A combination of two or more weaknesses.',
  };
  const statusTooltips: Record<string, string> = {
    Stable: 'Stable: This CWE entry is considered mature.',
    Incomplete: 'Incomplete: This entry has significant gaps.',
    Draft: 'Draft: A preliminary version not yet fully reviewed.',
    Deprecated: 'Deprecated: No longer recommended for use.',
  };

  return (
    <main className="container detail-page">
      {/* Header */}
      <div className="cwe-detail-header">
        <div>
          <div className="cwe-header-badges">
            <span className="cwe-detail-id">
              <Shield size={16} />
              CWE-{data.id}
            </span>
            {data.abstraction && (
              <span
                className={`cwe-abstraction-badge abstraction-${data.abstraction.toLowerCase()}`}
                title={abstractionTooltips[data.abstraction] || data.abstraction}
              >
                {data.abstraction}
              </span>
            )}
            {data.status && (
              <span
                className={`cwe-status-badge status-${data.status.toLowerCase()}`}
                title={statusTooltips[data.status] || data.status}
              >
                {data.status}
              </span>
            )}
          </div>
          <h1 className="cwe-detail-name">{data.name}</h1>
        </div>
        <a
          href={`https://cwe.mitre.org/data/definitions/${data.id}.html`}
          target="_blank"
          rel="noopener noreferrer"
          className="mitre-link"
        >
          <ExternalLink size={14} />
          View on MITRE
        </a>
      </div>

      {/* Platforms */}
      {data.applicable_platforms && data.applicable_platforms.length > 0 && (
        <div className="cwe-platforms-bar">
          <span className="platforms-label">
            <Cpu size={14} />
            Applies to:
          </span>
          <div className="platforms-tags">
            {data.applicable_platforms.map((p, i) => (
              <span key={i} className={`platform-tag platform-${p.type === 'Language' ? 'lang' : 'tech'}`}>
                {p.name}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Description */}
      <div className="detail-card">
        <h2>Description</h2>
        <p className="description">{data.description}</p>
        {data.extended_description && (
          <p className="ext-description">{data.extended_description}</p>
        )}
      </div>

      {/* Common Consequences */}
      {data.common_consequences && data.common_consequences.length > 0 && (
        <div className="detail-card">
          <h2><AlertTriangle size={18} /> Common Consequences</h2>
          <table className="consequences-table">
            <thead>
              <tr><th>Scope</th><th>Impact</th><th>Likelihood</th></tr>
            </thead>
            <tbody>
              {data.common_consequences.map((c, i) => (
                <tr key={i}>
                  <td><span className="scope-tag">{c.scope}</span></td>
                  <td>{c.impact}</td>
                  <td>
                    <span className={`likelihood-val ${c.likelihood ? 'likelihood-' + c.likelihood.toLowerCase() : ''}`}>
                      {c.likelihood || '-'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Potential Mitigations */}
      {data.potential_mitigations && data.potential_mitigations.length > 0 && (
        <div className="detail-card">
          <h2><Wrench size={18} /> Potential Mitigations</h2>
          {data.potential_mitigations.map((m, i) => (
            <div key={i} className="mitigation-item">
              <div className="mitigation-header">
                <span className="phase-badge">{m.phase}</span>
                {m.effectiveness && (
                  <span className={`effectiveness-badge effectiveness-${m.effectiveness.toLowerCase().replace(/\s+/g, '-')}`}>
                    {m.effectiveness}
                  </span>
                )}
              </div>
              <p className="mitigation-desc">{m.description}</p>
            </div>
          ))}
        </div>
      )}

      {/* Detection Methods */}
      {data.detection_methods && data.detection_methods.length > 0 && (
        <div className="detail-card">
          <h2><ScanSearch size={18} /> Detection Methods</h2>
          {data.detection_methods.map((d, i) => (
            <div key={i} className="detection-item">
              <div className="detection-header">
                <span className="method-badge">{d.method}</span>
                {d.effectiveness && (
                  <span className={`effectiveness-badge effectiveness-${d.effectiveness.toLowerCase().replace(/\s+/g, '-')}`}>
                    {d.effectiveness}
                  </span>
                )}
              </div>
              <p className="detection-desc">{d.description}</p>
            </div>
          ))}
        </div>
      )}

      {/* Affected Resources */}
      {data.affected_resources && data.affected_resources.length > 0 && (
        <div className="detail-card">
          <h2>Affected Resources</h2>
          <div className="platforms-tags">
            {data.affected_resources.map((r, i) => (
              <span key={i} className="resource-tag">{r}</span>
            ))}
          </div>
        </div>
      )}

      {/* Taxonomy Mappings */}
      {data.taxonomy_mappings && data.taxonomy_mappings.length > 0 && (
        <div className="detail-card">
          <h2>Taxonomy Mappings</h2>
          <table className="taxonomy-table">
            <thead>
              <tr><th>Taxonomy</th><th>ID</th><th>Entry Name</th></tr>
            </thead>
            <tbody>
              {data.taxonomy_mappings.map((m, i) => (
                <tr key={i}>
                  <td><span className="taxonomy-name">{m.taxonomy}</span></td>
                  <td>{m.entry_id || '-'}</td>
                  <td>{m.entry_name || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Related Weaknesses */}
      {data.related_weaknesses && data.related_weaknesses.length > 0 && (
        <div className="detail-card">
          <h2><GitBranch size={18} /> Related Weaknesses</h2>
          <div className="rel-grid">
            {(() => {
              const labels: Record<string, string> = {
                ChildOf: 'Parent Weakness',
                ParentOf: 'Child Weakness',
                PeerOf: 'Peer Weakness',
                CanPrecede: 'Can Lead To',
                CanFollow: 'Can Follow',
                StartsWith: 'Starts With',
                Requires: 'Requires',
              };
              const groups: Record<string, string[]> = {};
              data.related_weaknesses!.forEach((rel) => {
                const nature = rel.nature || 'Related';
                if (!groups[nature]) groups[nature] = [];
                groups[nature].push(rel.cwe_id);
              });

              return Object.entries(groups).map(([nature, ids]) => (
                <div key={nature} className="rel-group">
                  <span className="rel-group-label">{labels[nature] || nature}</span>
                  <div className="rel-group-tags">
                    {ids.map((cid) => (
                      <a key={cid} className="rel-chip" onClick={() => navigate(`/cwe/${cid}`)}>
                        CWE-{cid}
                      </a>
                    ))}
                  </div>
                </div>
              ));
            })()}
          </div>
        </div>
      )}

      {/* Associated CVEs */}
      <div className="detail-card">
        <div className="detail-card-header">
          <h2><Bug size={18} /> Associated CVEs</h2>
          {cves && <span className="cve-count-badge">{cves.length} CVEs</span>}
        </div>

        {cvesLoading && <Loading message="Fetching CVEs from NVD..." />}

        {cves && cves.length === 0 && (
          <p style={{ color: 'var(--text-secondary)', padding: '0.5rem 0' }}>
            No CVEs found for this CWE in the NVD database.
          </p>
        )}

        {cves && cves.length > 0 && (
          <table className="data-table">
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>Severity</th>
                <th>Score</th>
                <th>Published</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {cves.map((cve) => (
                <tr
                  key={cve.cve_id}
                  className="card-clickable"
                  onClick={() => navigate(`/cve/${cve.cve_id}`)}
                >
                  <td><strong className="cve-link">{cve.cve_id}</strong></td>
                  <td>
                    <SeverityBadge score={cve.cvss_v3} severity={cve.severity} />
                  </td>
                  <td>{cve.cvss_v3 != null ? cve.cvss_v3.toFixed(1) : 'N/A'}</td>
                  <td>{formatDate(cve.published)}</td>
                  <td className="desc-cell">{cve.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </main>
  );
}
