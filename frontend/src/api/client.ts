import type {
  Asset, DashboardStats, Diff, Graph, Observation, Policy, Scan, ScanDetail, ScopeAuth,
} from "../types";

const BASE = "/api";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch { /* ignore */ }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => req<Record<string, unknown>>("/health"),
  policies: () => req<Policy>("/policies"),

  // Scans
  listScans: (params?: { target?: string; status?: string }) => {
    const q = new URLSearchParams();
    if (params?.target) q.set("target", params.target);
    if (params?.status) q.set("status", params.status);
    return req<{ scans: Scan[]; total: number }>(`/scans?${q}`);
  },
  getScan: (id: string) => req<ScanDetail>(`/scans/${id}`),
  createScan: (body: {
    target: string;
    passive_only?: boolean;
    max_depth?: number;
    max_pages?: number;
    enable_subdomain_bruteforce?: boolean;
  }) => req<Scan>("/scans", { method: "POST", body: JSON.stringify(body) }),
  deleteScan: (id: string) =>
    req<{ message: string }>(`/scans/${id}`, { method: "DELETE" }),

  // Assets
  graph: (scanId: string) => req<Graph>(`/scans/${scanId}/graph`),
  assets: (
    scanId: string,
    params?: { type?: string; q?: string; min_score?: number },
  ) => {
    const q = new URLSearchParams();
    if (params?.type) q.set("type", params.type);
    if (params?.q) q.set("q", params.q);
    if (params?.min_score) q.set("min_score", String(params.min_score));
    return req<{ assets: Asset[]; total: number }>(
      `/scans/${scanId}/assets?${q}`,
    );
  },
  observations: (scanId: string, severity?: string) =>
    req<Observation[]>(
      `/scans/${scanId}/observations${severity ? `?severity=${severity}` : ""}`,
    ),

  // Stats / reports / scope
  stats: () => req<DashboardStats>("/stats"),
  createReport: (scanId: string) =>
    req<{ scan_id: string; target: string; format: string; generated_at: string; download_url: string }>(
      `/scans/${scanId}/report`, { method: "POST" },
    ),
  validateScope: (target: string, allow_private = false) =>
    req<ScopeAuth>("/scope/validate", {
      method: "POST",
      body: JSON.stringify({ target, allow_private_networks: allow_private }),
    }),
};
