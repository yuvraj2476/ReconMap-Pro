import { useState } from "react";
import { Server, Cloud, Globe2, ShieldCheck } from "lucide-react";
import { api } from "../api/client";
import { useApi } from "../hooks/useApi";
import PageHeader from "../components/PageHeader";
import { ScoreBadge, TypeBadge } from "../components/Badges";

export default function Infrastructure() {
  const scans = useApi(() => api.listScans({ status: "completed" }), []);
  const [scanId, setScanId] = useState<string | null>(null);
  const activeScan = scanId || scans.data?.scans[0]?.id;

  const assets = useApi(
    () => activeScan
      ? api.assets(activeScan)
      : Promise.resolve({ assets: [], total: 0 }),
    [activeScan],
  );

  const ips = assets.data?.assets.filter((a) => a.type === "ip") || [];
  const hosting = assets.data?.assets.filter((a) => a.type === "hosting") || [];
  const asns = assets.data?.assets.filter((a) => a.type === "asn") || [];
  const orgs = assets.data?.assets.filter((a) => a.type === "organization") || [];
  const certs = assets.data?.assets.filter((a) => a.type === "certificate") || [];
  const servers = assets.data?.assets.filter((a) => a.type === "web_server") || [];

  return (
    <div className="p-8 max-w-[1500px] mx-auto">
      <PageHeader
        title="Infrastructure"
        subtitle="IP addresses, ASN attribution, hosting providers and certificates"
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
          <Server className="w-10 h-10 mx-auto mb-3 opacity-40" />
          No completed scans yet.
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <Card title={`IP addresses (${ips.length})`} icon={<Globe2 className="w-4 h-4" />}>
            {ips.map((a) => {
              const p = a.properties as Record<string, unknown>;
              return (
                <div key={a.id} className="p-3 rounded-lg bg-ink-850/50 mb-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-sm">{a.name}</span>
                    <ScoreBadge score={a.attention_score} />
                  </div>
                  <div className="text-xs text-slate-400 mt-1 flex flex-wrap gap-x-3">
                    {p.asn ? <span>AS{String(p.asn)}</span> : null}
                    {p.org ? <span>{String(p.org)}</span> : null}
                    {p.cloud_provider ? (
                      <span className="text-teal-300">☁ {String(p.cloud_provider)}</span>
                    ) : null}
                    {p.country ? <span>{String(p.country)}</span> : null}
                  </div>
                </div>
              );
            })}
          </Card>

          <Card title={`ASNs / organizations (${asns.length + orgs.length})`} icon={<ShieldCheck className="w-4 h-4" />}>
            {asns.map((a) => (
              <div key={a.id} className="flex justify-between p-2 text-sm">
                <TypeBadge type={a.type} />
                <span className="font-mono text-xs">{a.name}</span>
              </div>
            ))}
            {orgs.map((a) => (
              <div key={a.id} className="flex justify-between p-2 text-sm">
                <TypeBadge type={a.type} />
                <span className="font-mono text-xs">{a.name}</span>
              </div>
            ))}
          </Card>

          <Card title={`Hosting / cloud (${hosting.length})`} icon={<Cloud className="w-4 h-4" />}>
            {hosting.map((a) => (
              <div key={a.id} className="flex items-center gap-2 p-2 text-sm">
                <Cloud className="w-3.5 h-3.5 text-teal-400" />
                <span>{a.name}</span>
              </div>
            ))}
          </Card>

          <Card title={`Web servers (${servers.length})`} icon={<Server className="w-4 h-4" />}>
            {servers.map((a) => (
              <div key={a.id} className="flex items-center gap-2 p-2 text-sm font-mono">
                <Server className="w-3.5 h-3.5 text-rose-400" />
                {a.name}
              </div>
            ))}
          </Card>

          <Card title={`Certificates (${certs.length})`} icon={<ShieldCheck className="w-4 h-4" />}>
            {certs.map((a) => {
              const p = a.properties as Record<string, unknown>;
              return (
                <div key={a.id} className="p-3 rounded-lg bg-ink-850/50 mb-2">
                  <div className="flex justify-between items-center">
                    <span className="font-mono text-xs">{a.name}</span>
                    <ScoreBadge score={a.attention_score} />
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    Issuer: {p.issuer ? String(p.issuer) : "—"} · SANs: {String(p.san_count ?? 0)}
                  </div>
                  {p.expired ? (
                    <div className="text-xs text-red-400 mt-1">⚠ Expired</div>
                  ) : null}
                </div>
              );
            })}
          </Card>
        </div>
      )}
    </div>
  );
}

function Card({
  title, icon, children,
}: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="card p-4">
      <h3 className="font-semibold flex items-center gap-2 mb-3 text-sm text-slate-300">
        {icon} {title}
      </h3>
      <div className="max-h-[420px] overflow-y-auto">{children}</div>
    </div>
  );
}
