import { useNavigate } from "react-router-dom";
import { useState } from "react";
import {
  Radar, Boxes, AlertTriangle, CheckCircle2, Clock, Shield,
  TrendingUp, Globe,
} from "lucide-react";
import { api } from "../api/client";
import { useApi } from "../hooks/useApi";
import PageHeader from "../components/PageHeader";
import NewScanModal from "../components/NewScanModal";
import { SeverityBadge, StatusPill, TypeBadge } from "../components/Badges";

export default function Dashboard() {
  const nav = useNavigate();
  const [modal, setModal] = useState(false);
  const stats = useApi(() => api.stats(), []);
  const scans = useApi(() => api.listScans(), []);
  const policies = useApi(() => api.policies(), []);

  const latest = stats.data?.latest_scan;
  const sev = stats.data?.severity_counts || {};
  const assetCounts = stats.data?.asset_counts || {};

  return (
    <div className="p-8 max-w-[1600px] mx-auto">
      <PageHeader
        title="Attack Surface Dashboard"
        subtitle="Authorization-first reconnaissance and asset intelligence"
        actions={
          <button className="btn-primary" onClick={() => setModal(true)}>
            <Radar className="w-4 h-4" /> New scan
          </button>
        }
      />

      {/* KPI cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <Kpi
          icon={<Radar className="w-5 h-5" />}
          label="Total scans"
          value={stats.data?.total_scans ?? "—"}
          tint="text-accent"
        />
        <Kpi
          icon={<CheckCircle2 className="w-5 h-5" />}
          label="Completed"
          value={stats.data?.completed_scans ?? "—"}
          tint="text-emerald-400"
        />
        <Kpi
          icon={<Boxes className="w-5 h-5" />}
          label="Assets in latest scan"
          value={latest ? Object.values(assetCounts).reduce((a, b) => a + b, 0) : "—"}
          tint="text-violet-400"
        />
        <Kpi
          icon={<AlertTriangle className="w-5 h-5" />}
          label="High observations"
          value={sev.high ?? 0}
          tint="text-red-400"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent scans */}
        <div className="lg:col-span-2 card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold flex items-center gap-2">
              <Clock className="w-4 h-4 text-slate-400" /> Recent scans
            </h2>
            <button className="text-xs text-accent hover:underline" onClick={() => nav("/scan")}>
              View all
            </button>
          </div>
          <table className="w-full">
            <thead>
              <tr>
                <th className="th">Target</th>
                <th className="th">Status</th>
                <th className="th">Progress</th>
                <th className="th">Created</th>
              </tr>
            </thead>
            <tbody>
              {scans.loading && (
                <tr><td className="td text-slate-500" colSpan={4}>Loading…</td></tr>
              )}
              {scans.data?.scans.slice(0, 6).map((s) => (
                <tr
                  key={s.id}
                  className="hover:bg-ink-700/40 cursor-pointer"
                  onClick={() => nav(`/scans/${s.id}`)}
                >
                  <td className="td font-mono text-xs">{s.target}</td>
                  <td className="td"><StatusPill status={s.status} /></td>
                  <td className="td w-48">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1.5 bg-ink-700 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-accent transition-all"
                          style={{ width: `${s.progress}%` }}
                        />
                      </div>
                      <span className="text-xs text-slate-400 w-9 text-right">
                        {Math.round(s.progress)}%
                      </span>
                    </div>
                  </td>
                  <td className="td text-xs text-slate-400">
                    {new Date(s.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
              {scans.data && scans.data.scans.length === 0 && (
                <tr>
                  <td colSpan={4} className="td text-center text-slate-500 py-8">
                    No scans yet. Click <strong>New scan</strong> to begin.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Security posture */}
        <div className="space-y-6">
          <div className="card p-5">
            <h2 className="font-semibold flex items-center gap-2 mb-4">
              <Shield className="w-4 h-4 text-emerald-400" /> Security observations
            </h2>
            {latest ? (
              <div className="space-y-2">
                {(["high", "medium", "low", "info"] as const).map((s) => (
                  <div key={s} className="flex items-center justify-between">
                    <SeverityBadge severity={s} />
                    <span className="font-mono text-lg">{sev[s] ?? 0}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-slate-500">Run a scan to see observations.</p>
            )}
          </div>

          <div className="card p-5">
            <h2 className="font-semibold flex items-center gap-2 mb-4">
              <TrendingUp className="w-4 h-4 text-accent" /> Asset breakdown
            </h2>
            {latest ? (
              <div className="space-y-2">
                {Object.entries(assetCounts)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 7)
                  .map(([type, count]) => (
                    <div key={type} className="flex items-center justify-between text-sm">
                      <TypeBadge type={type as never} />
                      <span className="font-mono">{count}</span>
                    </div>
                  ))}
              </div>
            ) : (
              <p className="text-sm text-slate-500">No data yet.</p>
            )}
          </div>
        </div>
      </div>

      {/* Policies */}
      <div className="card p-5 mt-6">
        <h2 className="font-semibold flex items-center gap-2 mb-2">
          <Globe className="w-4 h-4 text-slate-400" /> Safety policies
        </h2>
        <p className="text-sm text-slate-400 mb-4">
          {policies.data?.usage_requirement}
        </p>
        <div className="grid md:grid-cols-2 gap-4">
          <div>
            <h3 className="text-xs uppercase tracking-wider text-emerald-400 font-bold mb-2">
              Activities performed
            </h3>
            <ul className="space-y-1 text-xs text-slate-300">
              {policies.data?.allowed.slice(0, 6).map((a, i) => (
                <li key={i} className="flex gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" /> {a}
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="text-xs uppercase tracking-wider text-red-400 font-bold mb-2">
              Explicitly not performed
            </h3>
            <ul className="space-y-1 text-xs text-slate-300">
              {policies.data?.blocked.slice(0, 6).map((b, i) => (
                <li key={i} className="flex gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" /> {b}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      <NewScanModal
        open={modal}
        onClose={() => setModal(false)}
        onCreated={(id) => nav(`/scans/${id}`)}
      />
    </div>
  );
}

function Kpi({
  icon, label, value, tint,
}: { icon: React.ReactNode; label: string; value: React.ReactNode; tint: string }) {
  return (
    <div className="card p-5">
      <div className={`flex items-center gap-2 ${tint} mb-3`}>
        {icon}
        <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
          {label}
        </span>
      </div>
      <div className="text-3xl font-bold">{value}</div>
    </div>
  );
}
