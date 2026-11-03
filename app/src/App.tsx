import { useState, type CSSProperties } from "react";
import "./App.css";
import { useScan } from "./useScan";
import { useStatus } from "./useStatus";
import { BoxIcon, HomeIcon, ScanIcon, SettingsIcon, ShieldIcon } from "./icons";
import Dashboard from "./pages/Dashboard";
import ScanPage from "./pages/ScanPage";
import Quarantine from "./pages/Quarantine";
import SettingsPage from "./pages/SettingsPage";

export type Page = "dashboard" | "scan" | "quarantine" | "settings";

const NAV: { id: Page; label: string; Icon: typeof HomeIcon; color: string }[] = [
  { id: "dashboard", label: "Panoramica", Icon: HomeIcon, color: "var(--violet)" },
  { id: "scan", label: "Scansione", Icon: ScanIcon, color: "var(--cyan)" },
  { id: "quarantine", label: "Quarantena", Icon: BoxIcon, color: "var(--magenta)" },
  { id: "settings", label: "Impostazioni", Icon: SettingsIcon, color: "var(--lime)" },
];

export default function App() {
  const [page, setPage] = useState<Page>(() => {
    // In sviluppo: ?page=scan apre direttamente una pagina (utile per gli screenshot).
    const p = import.meta.env.DEV ? new URLSearchParams(location.search).get("page") : null;
    return p && NAV.some((n) => n.id === p) ? (p as Page) : "dashboard";
  });
  const scan = useScan();
  const status = useStatus();
  const running = scan.state.status === "running";

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">
            <ShieldIcon width={18} height={18} />
          </span>
          <span className="brand-name">Vigil</span>
        </div>
        <nav>
          {NAV.map(({ id, label, Icon, color }) => (
            <button
              key={id}
              className={`nav-item ${page === id ? "active" : ""}`}
              style={{ "--c": color } as CSSProperties}
              onClick={() => setPage(id)}
            >
              <Icon />
              <span>{label}</span>
              {id === "scan" && running && <span className="nav-pulse" title="Scansione in corso" />}
              {id === "quarantine" && (status.status?.quarantine_count ?? 0) > 0 && (
                <span className="nav-badge">{status.status?.quarantine_count}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-stripes" aria-hidden="true">
          <i />
          <i />
          <i />
        </div>
        <div className="sidebar-foot">v0.1.0 · fase 1</div>
      </aside>

      <main className="content">
        {page === "dashboard" && <Dashboard scan={scan} status={status} go={setPage} />}
        {page === "scan" && <ScanPage scan={scan} />}
        {page === "quarantine" && <Quarantine />}
        {page === "settings" && <SettingsPage status={status} />}
      </main>
    </div>
  );
}
