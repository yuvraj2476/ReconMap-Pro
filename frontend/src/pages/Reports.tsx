import { useState } from "react";
import { FileText, Download } from "lucide-react";
import { api } from "../api/client";
import { useApi } from "../hooks/useApi";
import PageHeader from "../components/PageHeader";

export default function Reports() {
  const scans = useApi(() => api.listScans({ status: "completed" }), []);
  const [busy, setBusy] = useState<string | null>(null);

  async function generate(scanId: string) {
    setBusy(scanId);
    try {
      const r = await api.createReport(scanId);
      window.open(r.download_url, "_blank");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="p-8 max-w-[1200px] mx-auto">
      <PageHeader
        title="Reports"
        subtitle="Generate professional HTML reports for completed scans"
      />

      <div className="card overflow-hidden">
        <table className="w-full">
          <thead className="bg-ink-850/50">
            <tr>
              <th className="th">Target</th>
              <th className="th">Completed</th>
              <th className="th">Assets</th>
              <th className="th">Observations</th>
              <th className="th w-40"></th>
            </tr>
          </thead>
          <tbody>
            {scans.data?.scans.map((s) => (
              <tr key={s.id} className="hover:bg-ink-700/40">
                <td className="td font-mono text-xs">{s.target}</td>
                <td className="td text-xs text-slate-400">
                  {s.completed_at ? new Date(s.completed_at).toLocaleString() : "—"}
                </td>
                <td className="td text-xs">—</td>
                <td className="td text-xs">—</td>
                <td className="td">
                  <button
                    className="btn-primary text-xs py-1.5"
                    onClick={() => generate(s.id)}
                    disabled={busy === s.id}
                  >
                    {busy === s.id ? "Generating…" : (
                      <>
                        <Download className="w-3.5 h-3.5" /> HTML report
                      </>
                    )}
                  </button>
                </td>
              </tr>
            ))}
            {scans.data && scans.data.scans.length === 0 && (
              <tr>
                <td colSpan={5} className="td text-center text-slate-500 py-12">
                  <FileText className="w-8 h-8 mx-auto mb-2 opacity-40" />
                  No completed scans to report on.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
