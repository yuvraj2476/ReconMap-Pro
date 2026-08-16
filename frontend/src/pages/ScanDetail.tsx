import { useParams, useNavigate } from "react-router-dom";
import { useState } from "react";
import {
  ArrowLeft, FileText, Network, AlertTriangle, Boxes,
  Loader2, CheckCircle2, XCircle,
} from "lucide-react";
import { api } from "../api/client";
import { useApi } from "../hooks/useApi";
import AttackGraph from "../components/AttackGraph";
import {
  SeverityBadge, ScoreBadge, StatusPill, TypeBadge,
} from "../components/Badges";

const STAGES = [
  "queued", "dns-enumeration", "subdomain-discovery", "ip-asn-attribution",
  "certificates", "http-analysis", "crawling", "javascript-analysis",
  "scoring", "completed",
];

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>();
  const nav = useNavigate();
  const [tab, setTab] = useState<"overview" | "graph" | "observations" | "assets">("overview");
  const [selected, setSelected] = useState<string | null>(null);

  const scan = useApi(
    () => api.getScan(scanId!),
    [scanId],
    // Poll while running
    2000,
  );
  const graph = useApi(
    () => api.graph(scanId!),
    [scanId],
    3000,
  );

  if (scan.loading || !scan.data) {
    return (
      <div className="flex items-center justify-center h-full text-slate-400">
        <Loader2 className="w-6 h-6 animate-spin mr-2" /> Loading scan…
      </div>
    );
  }

  const s = scan.data;
  const running = s.status === "running" || s.status === "pending";
  const stageIdx = STAGES.indexOf(s.stage);
  const selectedAsset = s.assets.find((a) => a.id === selected);

  async function downloadReport() {
    const r = await api.createReport(s.id);
    window.open(r.download_url, "_blank");
  }

  return (
    <div className="p-8 max-w-[1600px] mx-auto">
      <button
        onClick={() => nav("/scan")}
        className="btn-ghost mb-4 -ml-2"
      >
        <ArrowLeft className="w-4 h-4" /> Back to scans
      </button>

      <div className="flex flex-wrap items-start justify-between gap-4 mb-6">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold font-mono">{s.target}</h1>
            <StatusPill status={s.status} />
          </div>
          <p className="text-sm text-slate-400 mt-1">
            {s.id} · started {s.started_at ? new Date(s.started_at).toLocaleString() : "—"}
            {s.completed_at && ` · completed ${new Date(s.completed_at).toLocaleString()}`}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            className="btn-ghost"
            onClick={() => setTab("graph")}
            disabled={running}
          >
            <Network className="w-4 h-4" /> Graph
          </button>
          <button
            className="btn-primary"
            onClick={downloadReport}
            disabled={s.status !== "completed"}
          >
            <FileText className="w-4 h-4" /> Generate report
          </button>
        </div>
      </div>

      {/* Progress */}
      <div className="card p-5 mb-6">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium capitalize font-mono text-accent">
            {running && <Loader2 className="w-4 h-4 inline mr-1 animate-spin" />}
            {s.status === "completed" && <CheckCircle2 className="w-4 h-4 inline mr-1 text-emerald-400" />}
            {s.status === "failed" && <XCircle className="w-4 h-4 inline mr-1 text-red-400" />}
            {s.stage.replace(/-/g, " ")}
          </span>
          <span className="text-sm font-mono">{Math.round(s.progress)}%</span>
        </div>
        <div className="h-2 bg-ink-700 rounded-full overflow-hidden">
          <div
            className={`h-full transition-all duration-500 ${
              s.status === "failed" ? "bg-red-500" : "bg-gradient-to-r from-accent to-cyber-400"
            }`}
            style={{ width: `${s.progress}%` }}
          />
        </div>
        {s.error && (
          <pre className="mt-3 text-xs text-red-400 bg-red-500/10 p-3 rounded-lg overflow-auto max-h-32">
            {s.error}
          </pre>
        )}

        {/* Stage pipeline */}
        <div className="flex items-center gap-1 mt-4 overflow-x-auto pb-1">
          {STAGES.map((stage, i) => {
            const done = i < stageIdx || s.status === "completed";
            const active = i === stageIdx && running;
            return (
              <div key={stage} className="flex items-center">
                <div
                  className={`px-2.5 py-1 rounded text-[10px] font-mono whitespace-nowrap ${
                    done
                      ? "bg-emerald-500/15 text-emerald-400"
                      : active
                        ? "bg-accent/15 text-accent animate-pulse"
                        : "bg-ink-700/50 text-slate-500"
                  }`}
                >
                  {stage.replace(/-/g, " ")}
                </div>
                {i < STAGES.length - 1 && (
                  <div className="w-3 h-px bg-ink-600" />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-ink-700 mb-5">
        {([
          ["overview", "Overview", Boxes],
          ["graph", "Graph", Network],
          ["observations", "Observations", AlertTriangle],
          ["assets", `Assets (${s.asset_count})`, Boxes],
        ] as const).map(([key, label, Icon]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              tab === key
                ? "border-accent text-accent"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Icon className="w-4 h-4" /> {label}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <Stat label="Assets" value={s.asset_count} />
          <Stat label="Relations" value={s.relation_count} />
          <Stat label="Observations" value={s.observation_count} />

          {s.diffs.length > 0 && (
            <div className="card p-5 lg:col-span-3">
              <h3 className="font-semibold mb-3">Changes since previous scan</h3>
              <div className="space-y-1.5">
                {s.diffs.slice(0, 20).map((d) => (
                  <div key={d.id} className="flex items-center gap-3 text-sm">
                    <span className={`badge ${
                      d.change_type === "new" ? "bg-emerald-500/15 text-emerald-400" :
                      d.change_type === "removed" ? "bg-red-500/15 text-red-400" :
                      "bg-amber-500/15 text-amber-400"
                    }`}>{d.change_type}</span>
                    <TypeBadge type={d.asset_type as never} />
                    <span className="font-mono text-xs text-slate-300">{d.asset_name}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="card p-5 lg:col-span-3">
            <h3 className="font-semibold mb-3">Top observations</h3>
            <div className="space-y-2">
              {s.observations.slice(0, 8).map((o) => (
                <div key={o.id} className="flex items-start gap-3 p-3 rounded-lg bg-ink-850/50">
                  <SeverityBadge severity={o.severity} />
                  <div>
                    <div className="font-medium text-sm">{o.title}</div>
                    <div className="text-xs text-slate-400 mt-0.5">{o.description}</div>
                  </div>
                </div>
              ))}
              {s.observations.length === 0 && (
                <p className="text-sm text-slate-500">No observations.</p>
              )}
            </div>
          </div>
        </div>
      )}

      {tab === "graph" && (
        <div className="card p-2" style={{ height: "calc(100vh - 340px)", minHeight: 480 }}>
          {graph.data && graph.data.nodes.length > 0 ? (
            <div className="flex h-full gap-2">
              <div className="flex-1">
                <AttackGraph graph={graph.data} onSelect={setSelected} />
              </div>
              {selectedAsset && (
                <div className="w-80 shrink-0 p-4 border-l border-ink-700 overflow-y-auto">
                  <div className="flex items-center gap-2 mb-3">
                    <TypeBadge type={selectedAsset.type} />
                    <ScoreBadge score={selectedAsset.attention_score} />
                  </div>
                  <h3 className="font-mono text-sm break-all mb-3">{selectedAsset.name}</h3>
                  <dl className="space-y-2 text-xs">
                    <div>
                      <dt className="text-slate-500 uppercase tracking-wider">Source</dt>
                      <dd className="font-mono">{selectedAsset.source}</dd>
                    </div>
                    <div>
                      <dt className="text-slate-500 uppercase tracking-wider">Confidence</dt>
                      <dd>{Math.round(selectedAsset.confidence * 100)}%</dd>
                    </div>
                    {selectedAsset.evidence && (
                      <div>
                        <dt className="text-slate-500 uppercase tracking-wider">Evidence</dt>
                        <dd className="text-slate-300 break-words">{selectedAsset.evidence}</dd>
                      </div>
                    )}
                    {Object.keys(selectedAsset.properties).length > 0 && (
                      <div>
                        <dt className="text-slate-500 uppercase tracking-wider mb-1">Properties</dt>
                        <dd>
                          <pre className="bg-ink-850 p-2 rounded text-[10px] overflow-auto max-h-60">
                            {JSON.stringify(selectedAsset.properties, null, 2)}
                          </pre>
                        </dd>
                      </div>
                    )}
                  </dl>
                </div>
              )}
            </div>
          ) : (
            <div className="flex items-center justify-center h-full text-slate-500">
              {running ? "Graph will appear once the scan produces assets…" : "No graph data."}
            </div>
          )}
        </div>
      )}

      {tab === "observations" && (
        <div className="space-y-2">
          {s.observations.map((o) => (
            <div key={o.id} className="card p-4">
              <div className="flex items-start gap-3">
                <SeverityBadge severity={o.severity} />
                <div className="flex-1">
                  <div className="font-medium">{o.title}</div>
                  <p className="text-sm text-slate-400 mt-1">{o.description}</p>
                  {o.recommendation && (
                    <p className="text-sm text-emerald-300/80 mt-2">
                      <strong>Recommendation:</strong> {o.recommendation}
                    </p>
                  )}
                  <div className="flex gap-3 mt-2 text-[11px] text-slate-500 font-mono">
                    {o.cwe && <span>{o.cwe}</span>}
                    <span>source: {o.source}</span>
                  </div>
                </div>
              </div>
            </div>
          ))}
          {s.observations.length === 0 && (
            <p className="text-center text-slate-500 py-12">No observations.</p>
          )}
        </div>
      )}

      {tab === "assets" && (
        <div className="card overflow-hidden">
          <table className="w-full">
            <thead className="bg-ink-850/50">
              <tr>
                <th className="th">Score</th>
                <th className="th">Type</th>
                <th className="th">Name</th>
                <th className="th">Source</th>
                <th className="th">Confidence</th>
              </tr>
            </thead>
            <tbody>
              {s.assets.map((a) => (
                <tr
                  key={a.id}
                  className="hover:bg-ink-700/40 cursor-pointer"
                  onClick={() => {
                    setSelected(a.id);
                    setTab("graph");
                  }}
                >
                  <td className="td"><ScoreBadge score={a.attention_score} /></td>
                  <td className="td"><TypeBadge type={a.type} /></td>
                  <td className="td font-mono text-xs break-all">{a.name}</td>
                  <td className="td text-xs text-slate-400">{a.source}</td>
                  <td className="td text-xs">{Math.round(a.confidence * 100)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="card p-5">
      <div className="text-xs uppercase tracking-wider text-slate-400 mb-1">{label}</div>
      <div className="text-3xl font-bold text-accent">{value}</div>
    </div>
  );
}
