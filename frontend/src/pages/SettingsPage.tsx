import { Settings as SettingsIcon, Shield, Database, Cpu, Info } from "lucide-react";
import { api } from "../api/client";
import { useApi } from "../hooks/useApi";
import PageHeader from "../components/PageHeader";

export default function SettingsPage() {
  const health = useApi(() => api.health(), []);
  const policies = useApi(() => api.policies(), []);

  return (
    <div className="p-8 max-w-[1100px] mx-auto">
      <PageHeader title="Settings" subtitle="Platform configuration and safety policies" />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="card p-5">
          <h3 className="font-semibold flex items-center gap-2 mb-4">
            <Info className="w-4 h-4 text-accent" /> System
          </h3>
          <dl className="space-y-2 text-sm">
            <Row label="Application" value={String(health.data?.app ?? "—")} />
            <Row label="Environment" value={String(health.data?.environment ?? "—")} />
            <Row label="Database" value={String(health.data?.database ?? "—")} />
            <Row label="Queue" value={String(health.data?.redis ?? "—")} />
            <Row
              label="Private networks"
              value={health.data?.allow_private_networks ? "allowed" : "blocked"}
              danger={!health.data?.allow_private_networks}
            />
            <Row
              label="External tools auto-download"
              value={health.data?.allow_tool_download ? "allowed" : "blocked"}
              danger={!health.data?.allow_tool_download}
            />
          </dl>
        </div>

        <div className="card p-5">
          <h3 className="font-semibold flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-emerald-400" /> Safety policies
          </h3>
          <p className="text-xs text-slate-400 mb-3">
            {policies.data?.usage_requirement}
          </p>
          <div className="space-y-3">
            <div>
              <div className="text-[11px] uppercase tracking-wider text-emerald-400 font-bold mb-1">
                Allowed
              </div>
              <ul className="text-xs text-slate-300 space-y-1 list-disc list-inside">
                {policies.data?.allowed.map((a, i) => <li key={i}>{a}</li>)}
              </ul>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wider text-red-400 font-bold mb-1">
                Blocked
              </div>
              <ul className="text-xs text-slate-300 space-y-1 list-disc list-inside">
                {policies.data?.blocked.map((b, i) => <li key={i}>{b}</li>)}
              </ul>
            </div>
          </div>
        </div>

        <div className="card p-5 lg:col-span-2">
          <h3 className="font-semibold flex items-center gap-2 mb-3">
            <Database className="w-4 h-4 text-violet-400" /> Configuration
          </h3>
          <p className="text-sm text-slate-400 mb-3">
            ReconMap Pro is configured via environment variables prefixed with
            <code className="mx-1 text-accent">RECONMAP_</code>.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
            {[
              ["DATABASE_URL", "PostgreSQL (prod) or SQLite (dev)"],
              ["REDIS_URL", "Redis for arq workers (optional)"],
              ["ALLOW_PRIVATE_NETWORKS", "Enable scans of private networks"],
              ["ALLOW_TOOL_DOWNLOAD", "Enable subfinder auto-download"],
              ["SUBFINDER_SHODAN_API", "Shodan API Key for Subfinder"],
              ["SUBFINDER_VIRUSTOTAL_API", "VirusTotal API Key for Subfinder"],
              ["SUBFINDER_CENSYS_API", "Censys API credentials (ID:Secret)"],
              ["REQUEST_TIMEOUT", "Per-request HTTP timeout (s)"],
              ["MAX_CRAWL_DEPTH", "Crawler depth cap"],
              ["MAX_CRAWL_PAGES", "Crawler page cap"],
              ["MAX_CONCURRENT_REQUESTS", "Politeness limit"],
              ["PASSIVE_ONLY", "Disable active probing"],
              ["REPORT_DIR", "Report output directory"],
              ["CORS_ORIGINS", "Allowed frontend origins"],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between bg-ink-850 p-2 rounded">
                <span className="text-accent">{k}</span>
                <span className="text-slate-400 text-right">{v}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function Row({
  label, value, danger,
}: { label: string; value: string; danger?: boolean }) {
  return (
    <div className="flex justify-between border-b border-ink-700/50 pb-1.5">
      <dt className="text-slate-400">{label}</dt>
      <dd className={danger ? "text-emerald-400 font-mono text-xs" : "font-mono text-xs"}>
        {value}
      </dd>
    </div>
  );
}
