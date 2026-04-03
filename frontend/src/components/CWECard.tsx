import { useNavigate } from 'react-router-dom';
import { Shield, ArrowRight, Link2 } from 'lucide-react';
import type { CWESummary } from '../utils/types';

interface CWECardProps {
  cwe: CWESummary;
  index: number;
}

export default function CWECard({ cwe, index }: CWECardProps) {
  const navigate = useNavigate();
  const desc = cwe.description
    ? cwe.description.length > 180
      ? cwe.description.substring(0, 180) + '...'
      : cwe.description
    : 'No description available';

  const relCount = (cwe.related_weaknesses || []).length;

  return (
    <div
      className="cwe-card"
      style={{ animationDelay: `${index * 0.04}s` }}
      onClick={() => navigate(`/cwe/${cwe.id}`)}
    >
      <div className="cwe-card-accent"></div>
      <div className="cwe-card-body">
        <div className="cwe-card-header">
          <span className="cwe-card-id">
            <Shield size={13} />
            CWE-{cwe.id}
          </span>
          <span className="cwe-card-name">{cwe.name}</span>
        </div>
        <div className="cwe-card-desc">{desc}</div>
        <div className="cwe-card-meta">
          {relCount > 0 && (
            <span className="cwe-rel-count">
              <Link2 size={12} />
              {relCount} related
            </span>
          )}
          <span className="cwe-card-arrow">
            <ArrowRight size={14} />
          </span>
        </div>
      </div>
    </div>
  );
}
