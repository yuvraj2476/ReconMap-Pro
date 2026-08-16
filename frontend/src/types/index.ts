export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type AssetType =
  | "domain" | "subdomain" | "ip" | "asn" | "organization" | "certificate"
  | "technology" | "url" | "api" | "javascript" | "dns_record" | "hosting" | "web_server";
export type Severity = "info" | "low" | "medium" | "high";

export interface Scan {
  id: string;
  target: string;
  status: ScanStatus;
  progress: number;
  stage: string;
  message?: string;
  error?: string;
  passive_only: boolean;
  options: Record<string, unknown>;
  started_at?: string;
  completed_at?: string;
  created_at: string;
}

export interface ScanDetail extends Scan {
  asset_count: number;
  relation_count: number;
  observation_count: number;
  assets: Asset[];
  observations: Observation[];
  diffs: Diff[];
}

export interface Asset {
  id: string;
  scan_id: string;
  type: AssetType;
  name: string;
  properties: Record<string, unknown>;
  attention_score: number;
  confidence: number;
  source: string;
  evidence?: string;
  first_seen: string;
  last_seen: string;
}

export interface Observation {
  id: string;
  asset_id?: string;
  title: string;
  severity: Severity;
  description: string;
  recommendation?: string;
  cwe?: string;
  evidence?: string;
  source: string;
  created_at: string;
}

export interface Diff {
  id: string;
  baseline_scan_id?: string;
  change_type: "new" | "removed" | "changed";
  asset_type: string;
  asset_name: string;
  detail: Record<string, unknown>;
  created_at: string;
}

export interface GraphNode {
  data: {
    id: string;
    label: string;
    type: AssetType;
    color: string;
    icon: string;
    score: number;
    confidence: number;
    source: string;
    properties: Record<string, unknown>;
  };
}

export interface GraphEdge {
  data: {
    id: string;
    source: string;
    target: string;
    label: string;
    type: string;
    confidence: number;
    source_module: string;
    evidence?: string;
    timestamp?: string;
  };
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface DashboardStats {
  total_scans: number;
  completed_scans: number;
  latest_scan?: Scan;
  asset_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  technology_counts: Record<string, number>;
}

export interface Policy {
  usage_requirement: string;
  allowed: string[];
  blocked: string[];
}

export interface ScopeAuth {
  target: string;
  authorized: boolean;
  normalized: string;
  reason?: string;
}
