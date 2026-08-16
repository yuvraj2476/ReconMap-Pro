import { useParams, useNavigate } from "react-router-dom";
import { useState } from "react";
import { Network, ChevronRight } from "lucide-react";
import { api } from "../api/client";
import { useApi } from "../hooks/useApi";
import PageHeader from "../components/PageHeader";
import AttackGraph from "../components/AttackGraph";
import { ScoreBadge, TypeBadge } from "../components/Badges";

export default function GraphPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const nav = useNavigate();
  const [selected, setSelected] = useState<string | null>(null);

  // Determine which scan to show
  const listScans = useApi(() => api.listScans({ status: "completed" }), []);
  const activeScan = scanId || listScans.data?.scans[0]?.id;

  const graph = useApi(
    () => (activeScan ? api.graph(activeScan) : Promise.resolve({ nodes: [], edges: [] })),
    [activeScan],
  );
  const scan = useApi(
    () => (activeScan ? api.getScan(activeScan) : Promise.reject(new Error("no scan"))),
    [activeScan],
  );

  const nodes = graph.data?.nodes || [];
  const selectedNode = nodes.find((n) => n.data.id === selected);

  return (
    <div className="p-8 max-w-[1700px] mx-auto h-full flex flex-col">
      <PageHeader
        title="Attack Surface Graph"
        subtitle={
          activeScan
            ? `Interactive graph for ${scan.data?.target || activeScan}`
            : "Run a scan to visualize the attack surface"
        }
        actions={
          listScans.data && listScans.data.scans.length > 0 && (
            <select
              className="input w-64"
              value={activeScan}
              onChange={(e) => nav(`/graph/${e.target.value}`)}
            >
              {listScans.data.scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.target} — {new Date(s.created_at).toLocaleDateString()}
                </option>
              ))}
            </select>
          )
        }
      />

      <div className="flex-1 flex gap-4 min-h-0">
        <div className="flex-1 card p-2 relative">
          {nodes.length > 0 ? (
            <AttackGraph graph={graph.data!} onSelect={setSelected} />
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-slate-500">
              <Network className="w-12 h-12 mb-3 opacity-40" />
              <p>No graph data yet. Complete a scan to see relationships.</p>
            </div>
          )}
        </div>

        <aside className="w-80 shrink-0 space-y-4 overflow-y-auto">
          {selectedNode ? (
            <div className="card p-4">
              <div className="flex items-center gap-2 mb-3">
                <TypeBadge type={selectedNode.data.type} />
                <ScoreBadge score={selectedNode.data.score} />
              </div>
              <h3 className="font-mono text-sm break-all mb-3">
                {selectedNode.data.label}
              </h3>
              <dl className="space-y-2 text-xs">
                <div>
                  <dt className="text-slate-500 uppercase tracking-wider">Source</dt>
                  <dd className="font-mono">{selectedNode.data.source}</dd>
                </div>
                <div>
                  <dt className="text-slate-500 uppercase tracking-wider">Confidence</dt>
                  <dd>{Math.round(selectedNode.data.confidence * 100)}%</dd>
                </div>
                {Object.keys(selectedNode.data.properties).length > 0 && (
                  <div>
                    <dt className="text-slate-500 uppercase tracking-wider mb-1">Properties</dt>
                    <dd>
                      <pre className="bg-ink-850 p-2 rounded text-[10px] overflow-auto max-h-64">
                        {JSON.stringify(selectedNode.data.properties, null, 2)}
                      </pre>
                    </dd>
                  </div>
                )}
              </dl>
            </div>
          ) : (
            <div className="card p-4 text-sm text-slate-400">
              <div className="flex items-center gap-2 text-slate-200 font-semibold mb-2">
                <ChevronRight className="w-4 h-4" /> Click a node
              </div>
              Select any node to inspect its properties, evidence, source and
              confidence. Edges carry source, timestamp, confidence and evidence
              for every relationship.
            </div>
          )}

          <div className="card p-4">
            <h3 className="font-semibold text-sm mb-3">Legend</h3>
            <div className="space-y-1.5 text-xs">
              {[
                ["Domain", "#60a5fa"], ["Subdomain", "#38bdf8"], ["IP", "#a78bfa"],
                ["ASN", "#c084fc"], ["Certificate", "#fbbf24"], ["Technology", "#34d399"],
                ["URL", "#94a3b8"], ["API", "#fb923c"], ["JavaScript", "#facc15"],
                ["DNS", "#22d3ee"], ["Hosting", "#2dd4bf"],
              ].map(([label, color]) => (
                <div key={label} className="flex items-center gap-2">
                  <span
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: color as string }}
                  />
                  {label}
                </div>
              ))}
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
