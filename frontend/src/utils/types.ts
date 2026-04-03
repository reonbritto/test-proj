// ─── CWE Types ───────────────────────────────────────────
export interface CWESummary {
  id: string;
  name: string;
  description?: string;
  related_weaknesses?: { nature: string; cwe_id: string }[];
}

export interface CWEDetail extends CWESummary {
  abstraction?: string;
  status?: string;
  extended_description?: string;
  applicable_platforms?: { type: string; name: string }[];
  common_consequences?: { scope: string; impact: string; likelihood?: string }[];
  potential_mitigations?: { phase: string; description: string; effectiveness?: string }[];
  detection_methods?: { method: string; description: string; effectiveness?: string }[];
  affected_resources?: string[];
  taxonomy_mappings?: { taxonomy: string; entry_id?: string; entry_name?: string }[];
}

export interface Suggestion {
  type: string;
  text: string;
  action?: string;
}

// ─── CVE Types ───────────────────────────────────────────
export interface CVESummary {
  cve_id: string;
  description: string;
  cvss_v3: number | null;
  severity: string | null;
  published: string;
}

export interface CVEDetail {
  cve_id: string;
  description: string;
  published: string;
  modified: string;
  cvss: {
    v3_score: number | null;
    v3_severity: string | null;
    v3_vector: string | null;
    v2_score: number | null;
    v2_vector: string | null;
  };
  cwe_ids: string[];
  affected_products: { vendor: string; product: string; version: string }[];
  references: { url: string; tags: string[] }[];
}

// ─── ATT&CK Types ────────────────────────────────────────
export interface Tactic {
  id: string;
  name: string;
}

export interface Technique {
  id: string;
  name: string;
  description: string;
  tactics: string[];
  url: string;
  is_subtechnique?: boolean;
}

export interface CWEMapEntry {
  id: string;
  name: string;
}

export interface AttackMapping {
  techniques: (Technique & { tactics: string[] })[];
  tactics: Tactic[];
  cwe_sources: CWEMapEntry[];
  capec_ids: string[];
}

export interface TechniqueDetail {
  technique: Technique;
  subtechniques: Technique[];
  mapped_cwes: CWEMapEntry[];
}

// ─── Service Links ───────────────────────────────────────
export interface ServiceLinks {
  [key: string]: string;
}
