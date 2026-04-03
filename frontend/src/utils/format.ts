/**
 * Format ISO date string to readable format.
 */
export function formatDate(isoString: string | null | undefined): string {
  if (!isoString) return 'N/A';
  const d = new Date(isoString);
  return d.toLocaleDateString('en-GB', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/**
 * Get CSS class for severity level.
 */
export function severityClass(severity: string | null | undefined): string {
  if (!severity) return 'severity-unknown';
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
      return 'severity-critical';
    case 'HIGH':
      return 'severity-high';
    case 'MEDIUM':
      return 'severity-medium';
    case 'LOW':
      return 'severity-low';
    default:
      return 'severity-unknown';
  }
}

/**
 * Get CSS color for CVSS score.
 */
export function getScoreColor(score: number): string {
  if (score >= 9.0) return 'var(--severity-critical)';
  if (score >= 7.0) return 'var(--severity-high)';
  if (score >= 4.0) return 'var(--severity-medium)';
  return 'var(--severity-low)';
}

/**
 * ATT&CK tactic colors.
 */
export const TACTIC_COLORS: Record<string, string> = {
  TA0043: '#8b5cf6',
  TA0042: '#7c3aed',
  TA0001: '#dc2626',
  TA0002: '#ea580c',
  TA0003: '#d97706',
  TA0004: '#ca8a04',
  TA0005: '#65a30d',
  TA0006: '#16a34a',
  TA0007: '#0d9488',
  TA0008: '#0891b2',
  TA0009: '#2563eb',
  TA0011: '#4f46e5',
  TA0010: '#7c3aed',
  TA0040: '#be185d',
};

export const TACTIC_ORDER = [
  'TA0043', 'TA0042', 'TA0001', 'TA0002', 'TA0003',
  'TA0004', 'TA0005', 'TA0006', 'TA0007', 'TA0008',
  'TA0009', 'TA0011', 'TA0010', 'TA0040',
];
