import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Radar, Trash2 } from "lucide-react";
import { api } from "../api/client";
import { useApi } from "../hooks/useApi";
import PageHeader from "../components/PageHeader";
import NewScanModal from "../components/NewScanModal";
import { StatusPill } from "../components/Badges";

export default function ScanCenter() {
  const nav = useNavigate();
  const [modal, setModal] = useState(false);
  const scans = useApi(() => api.listScans(), []);

  async function remove(id: string, e: React.MouseEvent) {
    e.stopPropagation();
    if (!confirm("Delete this scan and all its assets?")) return;
    await api.deleteScan(id);
    scans.reload();
  }

  return (
    <div className="p-8 max-w-[1400px] mx-auto">
      <PageHeader
        title="Scan Center"
        subtitle="Launch, monitor and review authorized reconnaissance scans"
        actions={
          <button className="btn-primary" onClick={() => setModal(true)}>
            <Radar className="w-4 h-4" /> New scan
          </button>
        }
      />

      <div className="card overflow-hidden">
        <table className="w-full">
          <thead className="bg-ink-850/50">
            <tr>
              <th className="th">Target</th>
              <th className="th">Status</th>
              <th className="th">Stage</th>
              <th className="th">Progress</th>
              <th className="th">Created</th>
              <th className="th w-10"></th>
            </tr>
          </thead>
          <tbody>
            {scans.data?.scans.map((s) => (
              <tr
                key={s.id}
                className="hover:bg-ink-700/40 cursor-pointer"
                onClick={() => nav(`/scans/${s.id}`)}
              >
                <td className="td font-mono text-xs">{s.target}</td>
                <td className="td"><StatusPill status={s.status} /></td>
                <td className="td text-xs text-slate-400 font-mono">{s.stage}</td>
                <td className="td w-56">
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1.5 bg-ink-700 rounded-full overflow-hidden">
                      <div
                        className={`h-full transition-all ${
                          s.status === "failed" ? "bg-red-500" : "bg-accent"
                        }`}
                        style={{ width: `${s.progress}%` }}
                      />
                    </div>
                    <span className="text-xs text-slate-400 w-10 text-right">
                      {Math.round(s.progress)}%
                    </span>
                  </div>
                </td>
                <td className="td text-xs text-slate-400">
                  {new Date(s.created_at).toLocaleString()}
                </td>
                <td className="td">
                  {s.status !== "running" && (
                    <button
                      onClick={(e) => remove(s.id, e)}
                      className="text-slate-500 hover:text-red-400"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {scans.data && scans.data.scans.length === 0 && (
              <tr>
                <td colSpan={6} className="td text-center text-slate-500 py-12">
                  No scans yet. Start one to map an authorized domain.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <NewScanModal
        open={modal}
        onClose={() => setModal(false)}
        onCreated={(id) => nav(`/scans/${id}`)}
      />
    </div>
  );
}
