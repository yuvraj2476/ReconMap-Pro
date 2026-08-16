import clsx from "clsx";
import type { AssetType, Severity } from "../types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const map: Record<Severity, string> = {
    high: "bg-red-500/15 text-red-400 border border-red-500/30",
    medium: "bg-amber-500/15 text-amber-400 border border-amber-500/30",
    low: "bg-blue-500/15 text-blue-400 border border-blue-500/30",
    info: "bg-slate-500/15 text-slate-400 border border-slate-500/30",
  };
  return (
    <span className={clsx("badge capitalize", map[severity])}>{severity}</span>
  );
}

const TYPE_META: Record<AssetType, { label: string; color: string }> = {
  domain: { label: "Domain", color: "text-sky-400 bg-sky-500/10 border-sky-500/30" },
  subdomain: { label: "Subdomain", color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/30" },
  ip: { label: "IP", color: "text-violet-400 bg-violet-500/10 border-violet-500/30" },
  asn: { label: "ASN", color: "text-fuchsia-400 bg-fuchsia-500/10 border-fuchsia-500/30" },
  organization: { label: "Org", color: "text-pink-400 bg-pink-500/10 border-pink-500/30" },
  certificate: { label: "Cert", color: "text-amber-400 bg-amber-500/10 border-amber-500/30" },
  technology: { label: "Tech", color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30" },
  url: { label: "URL", color: "text-slate-300 bg-slate-500/10 border-slate-500/30" },
  api: { label: "API", color: "text-orange-400 bg-orange-500/10 border-orange-500/30" },
  javascript: { label: "JS", color: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30" },
  dns_record: { label: "DNS", color: "text-teal-400 bg-teal-500/10 border-teal-500/30" },
  hosting: { label: "Host", color: "text-teal-300 bg-teal-500/10 border-teal-500/30" },
  web_server: { label: "Server", color: "text-rose-400 bg-rose-500/10 border-rose-500/30" },
};

export function TypeBadge({ type }: { type: AssetType }) {
  const meta = TYPE_META[type];
  return (
    <span className={clsx("badge border", meta.color)}>{meta.label}</span>
  );
}

export function ScoreBadge({ score }: { score: number }) {
  const color =
    score >= 70
      ? "text-red-400 bg-red-500/10 border-red-500/30"
      : score >= 40
        ? "text-amber-400 bg-amber-500/10 border-amber-500/30"
        : "text-emerald-400 bg-emerald-500/10 border-emerald-500/30";
  return (
    <span className={clsx("badge border font-mono", color)}>
      {score}
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const map: Record<string, string> = {
    completed: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    running: "bg-accent/15 text-accent border-accent/30 animate-pulse",
    pending: "bg-slate-500/15 text-slate-400 border-slate-500/30",
    failed: "bg-red-500/15 text-red-400 border-red-500/30",
    cancelled: "bg-slate-500/15 text-slate-400 border-slate-500/30",
  };
  return (
    <span className={clsx("badge border capitalize", map[status] || map.pending)}>
      {status}
    </span>
  );
}
