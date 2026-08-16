import { NavLink, Route, Routes, Navigate } from "react-router-dom";
import {
  LayoutDashboard, Network, Boxes, Globe, Radar, Cpu, Server,
  History, FileText, Settings as SettingsIcon, Shield,
} from "lucide-react";
import clsx from "clsx";
import Dashboard from "./pages/Dashboard";
import GraphPage from "./pages/GraphPage";
import AssetExplorer from "./pages/AssetExplorer";
import DomainExplorer from "./pages/DomainExplorer";
import ScanCenter from "./pages/ScanCenter";
import TechIntelligence from "./pages/TechIntelligence";
import Infrastructure from "./pages/Infrastructure";
import HistoryPage from "./pages/HistoryPage";
import Reports from "./pages/Reports";
import SettingsPage from "./pages/SettingsPage";
import ScanDetail from "./pages/ScanDetail";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/graph", label: "Attack Surface Graph", icon: Network },
  { to: "/assets", label: "Asset Explorer", icon: Boxes },
  { to: "/domains", label: "Domain Explorer", icon: Globe },
  { to: "/scan", label: "Scan Center", icon: Radar },
  { to: "/tech", label: "Technology Intelligence", icon: Cpu },
  { to: "/infra", label: "Infrastructure", icon: Server },
  { to: "/history", label: "History", icon: History },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
];

export default function App() {
  return (
    <div className="flex h-full">
      {/* Sidebar */}
      <aside className="w-64 shrink-0 border-r border-ink-700 bg-ink-900/80 backdrop-blur flex flex-col">
        <div className="px-5 py-5 border-b border-ink-700">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-accent to-cyber-600 flex items-center justify-center shadow-lg shadow-accent/30">
              <Shield className="w-5 h-5 text-ink-950" strokeWidth={2.5} />
            </div>
            <div>
              <div className="font-bold text-slate-100 leading-tight">ReconMap</div>
              <div className="text-[10px] uppercase tracking-widest text-accent font-semibold">
                Pro
              </div>
            </div>
          </div>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                clsx(
                  "flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors",
                  isActive
                    ? "bg-accent/10 text-accent border border-accent/20"
                    : "text-slate-400 hover:text-slate-200 hover:bg-ink-700/50 border border-transparent"
                )
              }
            >
              <Icon className="w-4 h-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="p-3 border-t border-ink-700">
          <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 p-2.5">
            <div className="text-[10px] font-bold uppercase tracking-wider text-amber-400 mb-0.5">
              Authorized Use Only
            </div>
            <p className="text-[11px] leading-snug text-amber-200/80">
              For sanctioned security testing. Scope is enforced on every request.
            </p>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/graph" element={<GraphPage />} />
          <Route path="/graph/:scanId" element={<GraphPage />} />
          <Route path="/assets" element={<AssetExplorer />} />
          <Route path="/domains" element={<DomainExplorer />} />
          <Route path="/scan" element={<ScanCenter />} />
          <Route path="/scans/:scanId" element={<ScanDetail />} />
          <Route path="/tech" element={<TechIntelligence />} />
          <Route path="/infra" element={<Infrastructure />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
