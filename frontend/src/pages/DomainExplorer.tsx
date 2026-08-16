import { useState } from "react";
import { Globe, Network, Link2 } from "lucide-react";
import { api } from "../api/client";
import { useApi } from "../hooks/useApi";
import PageHeader from "../components/PageHeader";
import { ScoreBadge, TypeBadge } from "../components/Badges";

export default function DomainExplorer() {
  const scans = useApi(() => api.listScans({ status: "completed" }), []);
  const [scanId, setScanId] = useState<string | null>(null);
  const activeScan = scanId || scans.data?.scans[0]?.id;

  const assets = useApi(
    () => activeScan
      ? api.assets(activeScan)
      : Promise.resolve({ assets: [], total: 0 }),
    [activeScan],
  );

  const domains = assets.data?.assets.filter((a) => a.type === "domain" || a.type === "subdomain") || [];
  const dns = assets.data?.assets.filter((a) => a.type === "dns_record") || [];
  const urls = assets.data?.assets.filter((a) => a.type === "url") || [];

  return (
    <div className="p-8 max-w-[1500px] mx-auto">
      <PageHeader title="Domain Explorer" subtitle="Domains, subdomains and DNS records" />

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
        <Empty icon={<Globe className="w-10 h-10 opacity-40" />} text="No completed scans yet." />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          <Section title={`Domains & subdomains (${domains.length})`} icon={<Globe className="w-4 h-4" />}>
            {domains.map((a) => (
              <AssetRow key={a.id} name={a.name} score={a.attention_score} />
            ))}
          </Section>

          <Section title={`DNS records (${dns.length})`} icon={<Network className="w-4 h-4" />}>
            {dns.map((a) => (
              <AssetRow key={a.id} name={a.name} score={a.attention_score} small />
            ))}
          </Section>

          <Section title={`URLs (${urls.length})`} icon={<Link2 className="w-4 h-4" />}>
            {urls.slice(0, 50).map((a) => (
              <AssetRow key={a.id} name={a.name} score={a.attention_score} small />
            ))}
          </Section>
        </div>
      )}
    </div>
  );
}

function Section({
  title, icon, children,
}: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="card p-4">
      <h3 className="font-semibold flex items-center gap-2 mb-3 text-sm text-slate-300">
        {icon} {title}
      </h3>
      <div className="space-y-1 max-h-[600px] overflow-y-auto">
        {children}
      </div>
    </div>
  );
}

function AssetRow({ name, score, small }: { name: string; score: number; small?: boolean }) {
  return (
    <div className="flex items-center gap-2 p-2 rounded hover:bg-ink-700/40">
      <ScoreBadge score={score} />
      <span className={`font-mono text-slate-300 break-all ${small ? "text-[11px]" : "text-xs"}`}>
        {name}
      </span>
    </div>
  );
}

function Empty({ icon, text }: { icon: React.ReactNode; text: string }) {
  return (
    <div className="card p-12 text-center text-slate-500">
      <div className="flex justify-center mb-3">{icon}</div>
      {text}
    </div>
  );
}
