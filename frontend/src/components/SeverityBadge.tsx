import { severityClass } from '../utils/format';
import { AlertTriangle, AlertCircle, Info, CheckCircle, HelpCircle } from 'lucide-react';

interface SeverityBadgeProps {
  score: number | null | undefined;
  severity: string | null | undefined;
}

const iconMap: Record<string, React.ReactNode> = {
  CRITICAL: <AlertTriangle size={12} />,
  HIGH: <AlertCircle size={12} />,
  MEDIUM: <Info size={12} />,
  LOW: <CheckCircle size={12} />,
};

export default function SeverityBadge({ score, severity }: SeverityBadgeProps) {
  const cls = severityClass(severity);
  const label = severity || 'N/A';
  const scoreText = score != null ? score.toFixed(1) : '?';
  const icon = iconMap[(severity || '').toUpperCase()] || <HelpCircle size={12} />;

  return (
    <span className={`badge ${cls}`}>
      {icon}
      {scoreText} {label}
    </span>
  );
}
