import { useState } from "react";
import { X, Radar, ShieldCheck, AlertTriangle } from "lucide-react";
import { api } from "../api/client";
import type { ScopeAuth } from "../types";

export default function NewScanModal({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: (scanId: string) => void;
}) {
  const [target, setTarget] = useState("");
  const [passive, setPassive] = useState(false);
  const [activeSubs, setActiveSubs] = useState(false);
  const [maxDepth, setMaxDepth] = useState(2);
  const [maxPages, setMaxPages] = useState(40);
  const [scope, setScope] = useState<ScopeAuth | null>(null);
  const [checking, setChecking] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!open) return null;

  async function checkScope(value: string) {
    setTarget(value);
    setScope(null);
    if (value.length < 4) return;
    setChecking(true);
    try {
      const auth = await api.validateScope(value);
      setScope(auth);
    } catch {
      setScope(null);
    } finally {
      setChecking(false);
    }
  }

  async function submit() {
    setError(null);
    setSubmitting(true);
    try {
      const scan = await api.createScan({
        target,
        passive_only: passive,
        enable_subdomain_bruteforce: activeSubs,
        max_depth: maxDepth,
        max_pages: maxPages,
      });
      onCreated(scan.id);
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="card w-full max-w-lg p-6 shadow-2xl border-ink-600">
        <div className="flex items-start justify-between mb-5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-accent/15 flex items-center justify-center">
              <Radar className="w-5 h-5 text-accent" />
            </div>
            <div>
              <h2 className="font-bold text-lg">New authorized scan</h2>
              <p className="text-xs text-slate-400">
                Only scan domains you are explicitly authorized to test.
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300">
            <X className="w-5 h-5" />
          </button>
        </div>

        <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
          Target root domain
        </label>
        <input
          autoFocus
          className="input font-mono"
          placeholder="example.com"
          value={target}
          onChange={(e) => checkScope(e.target.value)}
        />

        {checking && (
          <p className="text-xs text-slate-400 mt-2">Validating scope…</p>
        )}
        {scope && !scope.authorized && (
          <div className="mt-3 flex items-start gap-2 rounded-lg bg-red-500/10 border border-red-500/30 p-3">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <p className="text-xs text-red-300">{scope.reason}</p>
          </div>
        )}
        {scope && scope.authorized && (
          <div className="mt-3 flex items-start gap-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 p-3">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <p className="text-xs text-emerald-300">
              Scope authorized for <span className="font-mono">{scope.normalized}</span>{" "}
              and all subdomains. Every active request will be validated.
            </p>
          </div>
        )}

        <div className="grid grid-cols-2 gap-4 mt-5">
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input
              type="checkbox"
              checked={passive}
              onChange={(e) => setPassive(e.target.checked)}
              className="accent-accent"
            />
            Passive-only mode
          </label>
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input
              type="checkbox"
              checked={activeSubs}
              onChange={(e) => setActiveSubs(e.target.checked)}
              disabled={passive}
              className="accent-accent"
            />
            Constrained subdomain wordlist
          </label>
        </div>

        <div className="mt-3 text-[11px] text-slate-400 bg-ink-850 p-2.5 rounded border border-ink-750">
          💡 <strong>Advanced Subdomain Recon:</strong> The scanner will automatically attempt to download and run <strong>subfinder</strong> if <code>RECONMAP_ALLOW_TOOL_DOWNLOAD=true</code> is set in the environment.
        </div>

        <div className="grid grid-cols-2 gap-4 mt-4">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Crawl depth</label>
            <input
              type="number"
              min={0}
              max={5}
              value={maxDepth}
              onChange={(e) => setMaxDepth(Number(e.target.value))}
              className="input"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Max pages</label>
            <input
              type="number"
              min={1}
              max={500}
              value={maxPages}
              onChange={(e) => setMaxPages(Number(e.target.value))}
              className="input"
            />
          </div>
        </div>

        {error && <p className="text-xs text-red-400 mt-3">{error}</p>}

        <div className="flex justify-end gap-2 mt-6">
          <button className="btn-ghost" onClick={onClose}>Cancel</button>
          <button
            className="btn-primary disabled:opacity-50"
            disabled={!scope?.authorized || submitting}
            onClick={submit}
          >
            <Radar className="w-4 h-4" />
            {submitting ? "Starting…" : "Start scan"}
          </button>
        </div>
      </div>
    </div>
  );
}
