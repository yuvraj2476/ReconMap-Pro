import { useState } from "react";
import { Cpu, ExternalLink } from "lucide-react";
import { api } from "../api/client";
import { useApi } from "../hooks/useApi";
import PageHeader from "../components/PageHeader";
import { ScoreBadge } from "../components/Badges";

export default function TechIntelligence() {
  const scans = useApi(() => api.listScans({ status: "completed" }), []);
  const [scanId, setScanId] = useState<string | null>(null);
  const activeScan = scanId || scans.data?.scans[0]?.id;

  const assets = useApi(
    () => activeScan
      ? api.assets(activeScan, { type: "technology" })
      : Promise.resolve({ assets: [], total: 0 }),
    [activeScan],
  );

  return (
    <div className="p-8 max-w-[1400px] mx-auto">
      <PageHeader
        title="Technology Intelligence"
        subtitle="Fingerprinted technologies, versions and categories"
      />

      <select
        className="input w-80 mb-5"
        value={activeScan || ""}
        onChange={(e) => setScanId(e.target.value)}
      >
        {scans.data?.scans.map((s) => (
          <option key={s.id} value={s.id}>
            {s.target} — {new Date(s.created_at).toLocaleDateString()}
          </option>
        ))}
      </select>

      {!activeScan ? (
        <div className="card p-12 text-center text-slate-500">
          <Cpu className="w-10 h-10 mx-auto mb-3 opacity-40" />
          No completed scans yet.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {assets.data?.assets.map((a) => {
            const props = a.properties as Record<string, unknown>;
            return (
              <div key={a.id} className="card p-4 hover:border-accent/40 transition-colors">
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div>
                    <h3 className="font-semibold text-slate-100">{a.name}</h3>
                    <p className="text-xs text-slate-400">{props.category ? String(props.category) : ""}</p>
                  </div>
                  <ScoreBadge score={a.attention_score} />
                </div>
                {props.version ? (
                  <div className="text-xs font-mono bg-ink-850 rounded px-2 py-1 inline-block mb-2">
                    v{String(props.version)}
                  </div>
                ) : null}
                {props.cpe ? (
                  <div className="text-[10px] text-slate-500 font-mono break-all">
                    {String(props.cpe)}
                  </div>
                ) : null}
                <div className="text-[10px] text-slate-500 mt-2">
                  source: {a.source} · {Math.round(a.confidence * 100)}% confidence
                </div>
                {a.evidence && (
                  <div className="mt-2 text-[11px] text-slate-400 bg-ink-850 p-2 rounded break-all">
                    {a.evidence}
                  </div>
                )}
              </div>
            );
          })}
          {assets.data && assets.data.assets.length === 0 && (
            <p className="text-slate-500 col-span-full text-center py-12">
              No technologies fingerprinted.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
