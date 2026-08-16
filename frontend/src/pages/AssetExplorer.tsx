import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Search, Boxes, ChevronRight } from "lucide-react";
import { api } from "../api/client";
import { useApi } from "../hooks/useApi";
import PageHeader from "../components/PageHeader";
import { ScoreBadge, TypeBadge } from "../components/Badges";
import type { AssetType } from "../types";

const TYPES: AssetType[] = [
  "domain", "subdomain", "ip", "asn", "organization", "certificate",
  "technology", "url", "api", "javascript", "dns_record", "hosting", "web_server",
];

export default function AssetExplorer() {
  const nav = useNavigate();
  const scans = useApi(() => api.listScans({ status: "completed" }), []);
  const [scanId, setScanId] = useState<string | null>(null);
  const [type, setType] = useState<string>("");
  const [q, setQ] = useState("");

  const activeScan = scanId || scans.data?.scans[0]?.id;
  const assets = useApi(
    () => activeScan
      ? api.assets(activeScan, { type: type || undefined, q: q || undefined })
      : Promise.resolve({ assets: [], total: 0 }),
    [activeScan, type, q],
  );

  return (
    <div className="p-8 max-w-[1500px] mx-auto">
      <PageHeader
        title="Asset Explorer"
        subtitle="Search and filter every discovered asset across the attack surface"
      />

      <div className="flex flex-wrap gap-3 mb-5">
        <select
          className="input w-72"
          value={activeScan || ""}
          onChange={(e) => setScanId(e.target.value)}
        >
          {scans.data?.scans.map((s) => (
            <option key={s.id} value={s.id}>
              {s.target} — {new Date(s.created_at).toLocaleDateString()}
            </option>
          ))}
        </select>

        <div className="relative flex-1 min-w-64">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            className="input pl-9"
            placeholder="Search asset names…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>

        <select className="input w-44" value={type} onChange={(e) => setType(e.target.value)}>
          <option value="">All types</option>
          {TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </div>

      {!activeScan ? (
        <div className="card p-12 text-center text-slate-500">
          <Boxes className="w-10 h-10 mx-auto mb-3 opacity-40" />
          No completed scans yet.
        </div>
      ) : (
        <div className="card overflow-hidden">
          <table className="w-full">
            <thead className="bg-ink-850/50">
              <tr>
                <th className="th w-16">Score</th>
                <th className="th w-28">Type</th>
                <th className="th">Name</th>
                <th className="th w-32">Source</th>
                <th className="th w-24">Confidence</th>
                <th className="th w-10"></th>
              </tr>
            </thead>
            <tbody>
              {assets.data?.assets.map((a) => (
                <tr key={a.id} className="hover:bg-ink-700/40">
                  <td className="td"><ScoreBadge score={a.attention_score} /></td>
                  <td className="td"><TypeBadge type={a.type} /></td>
                  <td className="td font-mono text-xs break-all">{a.name}</td>
                  <td className="td text-xs text-slate-400">{a.source}</td>
                  <td className="td text-xs">{Math.round(a.confidence * 100)}%</td>
                  <td className="td">
                    <button
                      onClick={() => nav(`/scans/${a.scan_id}`)}
                      className="text-slate-500 hover:text-accent"
                    >
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
              {assets.data && assets.data.assets.length === 0 && (
                <tr>
                  <td colSpan={6} className="td text-center text-slate-500 py-10">
                    No matching assets.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
