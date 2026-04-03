import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search, X, ExternalLink, Crosshair, Shield, Layers,
  Target, ChevronRight, GitBranch,
} from 'lucide-react';
import Loading from '../components/Loading';
import { useApi } from '../hooks/useApi';
import { TACTIC_COLORS, TACTIC_ORDER } from '../utils/format';
import type { Tactic, Technique, CWEMapEntry, TechniqueDetail } from '../utils/types';
import { fetchAPI } from '../utils/api';

export default function AttackMatrix() {
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState('');
  const [showMappedOnly, setShowMappedOnly] = useState(false);
  const [selectedTech, setSelectedTech] = useState<TechniqueDetail | null>(null);
  const [panelLoading, setPanelLoading] = useState(false);

  const { data: tactics, isLoading: tacticsLoading } = useApi<Tactic[]>('attack-tactics', '/api/attack/tactics');
  const { data: techniques, isLoading: techLoading } = useApi<Technique[]>('attack-techniques', '/api/attack/techniques');
  const { data: cweMap, isLoading: cweMapLoading } = useApi<Record<string, CWEMapEntry[]>>('attack-cwe-map', '/api/attack/cwe-map');

  const isLoading = tacticsLoading || techLoading || cweMapLoading;

  const stats = useMemo(() => {
    if (!techniques || !cweMap) return { total: 0, mapped: 0, cwes: 0 };
    const mappedCount = Object.keys(cweMap).length;
    const totalCWEs = new Set<string>();
    Object.values(cweMap).forEach((cwes) => cwes.forEach((c) => totalCWEs.add(c.id)));
    return { total: techniques.length, mapped: mappedCount, cwes: totalCWEs.size };
  }, [techniques, cweMap]);

  const sortedTactics = useMemo(() => {
    if (!tactics) return [];
    return [...tactics].sort((a, b) => {
      const ai = TACTIC_ORDER.indexOf(a.id);
      const bi = TACTIC_ORDER.indexOf(b.id);
      return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
    });
  }, [tactics]);

  const showTechDetail = async (techId: string) => {
    setPanelLoading(true);
    try {
      const data = await fetchAPI<TechniqueDetail>(`/api/attack/technique/${techId}`);
      setSelectedTech(data);
    } catch (err) {
      console.error('Failed to load technique:', err);
    } finally {
      setPanelLoading(false);
    }
  };

  if (isLoading) {
    return <main className="container"><Loading message="Loading ATT&CK matrix..." /></main>;
  }

  if (!tactics || !techniques || !cweMap) {
    return (
      <main className="container">
        <div className="error-message">
          <p>Failed to load ATT&CK data.</p>
          <p style={{ marginTop: '1rem' }}>
            <a href="/" style={{ color: 'var(--accent-blue)' }}>Return to Home</a>
          </p>
        </div>
      </main>
    );
  }

  return (
    <main className="container attack-page">
      {/* Hero Header */}
      <div className="attack-page-header">
        <div className="attack-header-icon">
          <Crosshair size={32} />
        </div>
        <h1>MITRE ATT&CK Enterprise Matrix</h1>
        <p>Adversary techniques mapped to CWE software weaknesses. Click any technique to see details.</p>
      </div>

      {/* Stats Cards */}
      <div className="attack-stats-grid">
        <div className="attack-stat-card">
          <div className="attack-stat-icon"><Layers size={20} /></div>
          <div className="attack-stat-content">
            <span className="attack-stat-val">{stats.total}</span>
            <span className="attack-stat-label">Total Techniques</span>
          </div>
        </div>
        <div className="attack-stat-card attack-stat-highlight">
          <div className="attack-stat-icon"><Target size={20} /></div>
          <div className="attack-stat-content">
            <span className="attack-stat-val">{stats.mapped}</span>
            <span className="attack-stat-label">CWE Mapped</span>
          </div>
        </div>
        <div className="attack-stat-card">
          <div className="attack-stat-icon"><Shield size={20} /></div>
          <div className="attack-stat-content">
            <span className="attack-stat-val">{stats.cwes}</span>
            <span className="attack-stat-label">Unique CWEs</span>
          </div>
        </div>
      </div>

      {/* Toolbar */}
      <div className="attack-toolbar">
        <div className="attack-search-wrapper">
          <Search size={16} className="attack-search-icon" />
          <input
            type="text"
            placeholder="Search techniques by ID or name..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="attack-search-input"
          />
          {searchQuery && (
            <button className="attack-search-clear" onClick={() => setSearchQuery('')}>
              <X size={14} />
            </button>
          )}
        </div>

        <label className="attack-toggle-label">
          <input
            type="checkbox"
            checked={showMappedOnly}
            onChange={(e) => setShowMappedOnly(e.target.checked)}
          />
          <span className="attack-toggle-switch"></span>
          <span>CWE mapped only</span>
        </label>
      </div>

      {/* Legend */}
      <div className="attack-legend">
        <div className="attack-legend-item">
          <span className="attack-legend-swatch attack-legend-mapped"></span>
          <span>CWE mapped technique</span>
        </div>
        <div className="attack-legend-item">
          <span className="attack-legend-swatch attack-legend-unmapped"></span>
          <span>Unmapped technique</span>
        </div>
        <div className="attack-legend-item">
          <span className="attack-cwe-count-dot" style={{ fontSize: '0.55rem', minWidth: '16px', height: '16px' }}>n</span>
          <span>Mapped CWE count</span>
        </div>
      </div>

      {/* Matrix Grid */}
      <div className="attack-matrix-grid">
        {sortedTactics.map((tactic) => {
          const color = TACTIC_COLORS[tactic.id] || '#6b7280';
          const tacticTechs = techniques
            .filter((t) => t.tactics.includes(tactic.id))
            .sort((a, b) => {
              const aMapped = cweMap[a.id] ? 1 : 0;
              const bMapped = cweMap[b.id] ? 1 : 0;
              if (bMapped !== aMapped) return bMapped - aMapped;
              return a.name.localeCompare(b.name);
            });

          const filteredTechs = tacticTechs.filter((t) => {
            const q = searchQuery.toLowerCase();
            const textMatch = !q || t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q);
            const mappedMatch = !showMappedOnly || (cweMap[t.id] && cweMap[t.id].length > 0);
            return textMatch && mappedMatch;
          });

          if (filteredTechs.length === 0 && (searchQuery || showMappedOnly)) return null;

          const mappedInTactic = tacticTechs.filter((t) => cweMap[t.id]).length;

          return (
            <div key={tactic.id} className="attack-matrix-column">
              <div className="attack-matrix-tactic-header" style={{ background: color }}>
                <span className="attack-matrix-tactic-name">{tactic.name}</span>
                <span className="attack-matrix-tactic-count">
                  {mappedInTactic}/{tacticTechs.length} mapped
                </span>
              </div>
              <div className="attack-matrix-techniques">
                {filteredTechs.map((tech) => {
                  const cwes = cweMap[tech.id];
                  const hasCWE = cwes && cwes.length > 0;
                  const isSelected = selectedTech?.technique.id === tech.id;
                  return (
                    <div
                      key={tech.id}
                      className={`attack-matrix-tech-cell${hasCWE ? ' has-cwe-mapping' : ''}${isSelected ? ' active' : ''}`}
                      onClick={() => showTechDetail(tech.id)}
                    >
                      <div className="attack-cell-top">
                        <span className="attack-matrix-tech-id">{tech.id}</span>
                        {hasCWE && (
                          <span className="attack-cwe-count-dot" title={`${cwes.length} CWE(s): ${cwes.map(c => 'CWE-' + c.id).join(', ')}`}>
                            {cwes.length}
                          </span>
                        )}
                      </div>
                      <span className="attack-matrix-tech-name">{tech.name}</span>
                      {hasCWE && (
                        <div className="attack-cell-cwes">
                          {cwes.slice(0, 3).map(c => (
                            <span key={c.id} className="attack-cell-cwe-tag">CWE-{c.id}</span>
                          ))}
                          {cwes.length > 3 && <span className="attack-cell-cwe-more">+{cwes.length - 3}</span>}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      {/* Technique Detail Panel */}
      {(selectedTech || panelLoading) && (
        <div className="technique-panel">
          <button className="close-panel-btn" onClick={() => setSelectedTech(null)} aria-label="Close">
            <X size={18} />
          </button>

          {panelLoading ? (
            <Loading message="Loading technique..." />
          ) : selectedTech && (
            <>
              <div className="tech-panel-header">
                <span className="tech-panel-id">{selectedTech.technique.id}</span>
                <h3>{selectedTech.technique.name}</h3>
              </div>

              {/* Tactic pills */}
              <div className="tech-panel-tactics">
                {selectedTech.technique.tactics.map((tid) => {
                  const tactic = tactics.find((t) => t.id === tid);
                  return tactic ? (
                    <span key={tid} className="attack-tactic-pill" style={{ background: TACTIC_COLORS[tid] || '#6b7280' }}>
                      {tactic.name}
                    </span>
                  ) : null;
                })}
              </div>

              <p className="tech-panel-desc">{selectedTech.technique.description}</p>

              <a
                href={selectedTech.technique.url || `https://attack.mitre.org/techniques/${selectedTech.technique.id.replace('.', '/')}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="mitre-link"
              >
                <ExternalLink size={14} />
                View on MITRE ATT&CK
              </a>

              {/* Sub-techniques */}
              {selectedTech.subtechniques && selectedTech.subtechniques.length > 0 && (
                <div className="tech-panel-section">
                  <h4><GitBranch size={15} /> Sub-techniques ({selectedTech.subtechniques.length})</h4>
                  <div className="tech-panel-subs">
                    {selectedTech.subtechniques.map((sub) => {
                      const subCwes = cweMap[sub.id];
                      const subHasCwe = subCwes && subCwes.length > 0;
                      return (
                        <a
                          key={sub.id}
                          className={`attack-sub-chip${subHasCwe ? ' has-cwe-mapping' : ''}`}
                          href={sub.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          title={subHasCwe ? `Mapped to ${subCwes.length} CWE(s)` : undefined}
                        >
                          <span className="attack-sub-id">{sub.id}</span>
                          <span>{sub.name}</span>
                          {subHasCwe && <span className="attack-cwe-count-dot">{subCwes.length}</span>}
                          <ChevronRight size={12} className="sub-chip-arrow" />
                        </a>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Mapped CWEs */}
              {selectedTech.mapped_cwes && selectedTech.mapped_cwes.length > 0 && (
                <div className="tech-panel-section">
                  <h4><Shield size={15} /> Mapped CWEs ({selectedTech.mapped_cwes.length})</h4>
                  <div className="tech-panel-cwes">
                    {selectedTech.mapped_cwes.map((cwe) => (
                      <div key={cwe.id} className="attack-cwe-chip" onClick={() => navigate(`/cwe/${cwe.id}`)}>
                        <div className="attack-cwe-chip-header">
                          <span className="attack-cwe-chip-id">CWE-{cwe.id}</span>
                          <ChevronRight size={12} className="cwe-chip-arrow" />
                        </div>
                        <span className="attack-cwe-chip-name">{cwe.name}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </main>
  );
}
