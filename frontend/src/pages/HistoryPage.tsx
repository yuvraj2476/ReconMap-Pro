import { useState } from "react";
import { History as HistoryIcon, Plus, Minus, RefreshCw } from "lucide-react";
import { api } from "../api/client";
import { useApi } from "../hooks/useApi";
import PageHeader from "../components/PageHeader";
import { TypeBadge } from "../components/Badges";

export default function HistoryPage() {
  const scans = useApi(() => api.listScans({ status: "completed" }), []);
  const [scanId, setScanId] = useState<string | null>(null);
  const activeScan = scanId || scans.data?.scans[0]?.id;

  const scan = useApi(
    () => activeScan ? api.getScan(activeScan) : Promise.reject(new Error("no scan")),
    [activeScan],
  );

  const diffs = scan.data?.diffs || [];

  return (
    <div className="p-8 max-w-[1300px] mx-auto">
      <PageHeader
        title="Scan History"
        subtitle="Detect new, removed and changed assets between scans"
      />

      <select
        className="input w-96 mb-5"
        value={activeScan || ""}
        onChange={(e) => setScanId(e.target.value)}
      >
        {scans.data?.scans.map((s) => (
          <option key={s.id} value={s.id}>
            {s.target} — {new Date(s.created_at).toLocaleString()}
          </option>
        ))}
      </select>

      {!activeScan ? (
        <div className="card p-12 text-center text-slate-500">
          <HistoryIcon className="w-10 h-10 mx-auto mb-3 opacity-40" />
          Run at least two scans against the same target to see history.
        </div>
      ) : (
        <div className="card p-5">
          {diffs.length === 0 ? (
            <div className="text-center py-12 text-slate-500">
              <RefreshCw className="w-8 h-8 mx-auto mb-3 opacity-40" />
              <p>No changes detected — this is the first completed scan for this target,</p>
              <p>or the surface has remained stable since the previous scan.</p>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr>
                  <th className="th">Change</th>
                  <th className="th">Asset type</th>
                  <th className="th">Asset</th>
                  <th className="th">Detail</th>
                </tr>
              </thead>
              <tbody>
                {diffs.map((d) => (
                  <tr key={d.id}>
                    <td className="td">
                      <span className={`badge ${
                        d.change_type === "new"
                          ? "bg-emerald-500/15 text-emerald-400"
                          : d.change_type === "removed"
                            ? "bg-red-500/15 text-red-400"
                            : "bg-amber-500/15 text-amber-400"
                      }`}>
                        {d.change_type === "new" && <Plus className="w-3 h-3" />}
                        {d.change_type === "removed" && <Minus className="w-3 h-3" />}
                        {d.change_type === "changed" && <RefreshCw className="w-3 h-3" />}
                        {d.change_type}
                      </span>
                    </td>
                    <td className="td"><TypeBadge type={d.asset_type as never} /></td>
                    <td className="td font-mono text-xs">{d.asset_name}</td>
                    <td className="td text-xs text-slate-400 font-mono">
                      {Object.keys(d.detail).length > 0
                        ? JSON.stringify(d.detail).slice(0, 120)
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
