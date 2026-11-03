import { useEffect, useRef } from "react";
import { api, formatAgo, nf, rtState, type RtEvent } from "../api";
import type { RealtimeController } from "../useRealtime";
import type { ScanController } from "../useScan";
import type { StatusController } from "../useStatus";
import type { Page } from "../App";
import {
  BoltIcon,
  DriveIcon,
  FolderIcon,
  RefreshIcon,
  SettingsIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  ShieldIcon,
} from "../icons";

type ModuleState = "on" | "busy" | "off" | "warn";

const KICKER = {
  ok: "Protetto",
  warn: "Attenzione",
  danger: "Minaccia",
  neutral: "Vigil",
} as const;

interface Props {
  scan: ScanController;
  status: StatusController;
  rt: RealtimeController;
  go: (p: Page) => void;
}

export default function Dashboard({ scan, status: st, rt, go }: Props) {
  const { status: scanStatus, lastScan, summary } = scan.state;
  const s = st.status;
  const rs = rtState(rt.status);
  const rts = rt.status?.status;

  const quick = () => {
    scan.start("quick");
    go("scan");
  };
  const full = () => {
    scan.start("full");
    go("scan");
  };

  // ── Hero ──
  let tone: "ok" | "warn" | "danger" | "neutral" = "neutral";
  let title = "Nessuna scansione eseguita";
  let subtitle = "Avvia una scansione rapida per controllare le cartelle più a rischio.";
  let Icon = ShieldIcon;
  const detections = (x: typeof summary) => x.infected + x.suspicious;
  const { threats, handled } = scan.state;
  const unresolved = threats.filter(
    (t) => t.verdict.kind === "infected" && (!handled[t.path] || handled[t.path].kind === "failed"),
  ).length;
  if (!lastScan && rs === "active") {
    tone = "ok";
    Icon = ShieldCheckIcon;
    title = "Protezione in tempo reale attiva";
    subtitle = "Vigil controlla ogni programma prima che venga eseguito e ogni file appena scritto.";
  }
  if (scanStatus === "running") {
    title = "Scansione in corso…";
    subtitle = `${nf.format(summary.scanned)} file analizzati finora`;
  } else if (lastScan && lastScan.summary.infected > 0 && unresolved === 0) {
    tone = "ok";
    Icon = ShieldCheckIcon;
    title = "Minacce neutralizzate";
    subtitle = `Le ${lastScan.summary.infected} minacce dell'ultima scansione sono state gestite.`;
  } else if (lastScan && lastScan.summary.infected > 0) {
    tone = "danger";
    Icon = ShieldAlertIcon;
    title = `${unresolved} ${unresolved === 1 ? "minaccia da gestire" : "minacce da gestire"}`;
    subtitle = "Mettile in quarantena dalla pagina Scansione.";
  } else if (lastScan && lastScan.summary.suspicious > 0) {
    tone = "warn";
    Icon = ShieldAlertIcon;
    title = `${lastScan.summary.suspicious} ${lastScan.summary.suspicious === 1 ? "file sospetto" : "file sospetti"}`;
    subtitle = "Nessuna minaccia certa, ma alcuni file meritano un'occhiata.";
  } else if (lastScan) {
    tone = lastScan.summary.cancelled ? "warn" : "ok";
    Icon = ShieldCheckIcon;
    title = lastScan.summary.cancelled ? "Ultima scansione interrotta" : "Nessuna minaccia rilevata";
    subtitle = `Ultima scansione: ${lastScan.finishedAt.toLocaleString("it-IT")} · ${nf.format(lastScan.summary.scanned)} file`;
  }

  // ── Moduli ──
  const clam = s?.clamav;
  const clamState: [ModuleState, string, string] = !s?.clamav_enabled
    ? ["off", "Disattivato", "Attivalo nelle impostazioni"]
    : !clam?.installed
      ? ["warn", "Da configurare", "Cartella di ClamAV non valida"]
      : !clam.database
        ? ["warn", "Senza firme", "Premi “Aggiorna firme”"]
        : clam.running
          ? ["on", "Attivo", clam.version?.split("/").slice(0, 2).join(" · firme ") ?? "clamd in ascolto"]
          : clam.starting
            ? ["busy", "Avvio…", "Caricamento di milioni di firme (fino a un minuto)"]
            : ["warn", "Fermo", st.clamavError ?? "clamd non è in esecuzione"];

  const rtModule: { desc: string; state: ModuleState; label: string } = {
    not_installed: { state: "off" as const, label: "Non installata", desc: "Richiede il driver VigilFlt (per ora solo nella VM di test)" },
    stopped: { state: "warn" as const, label: "Disattivata", desc: "Il servizio VigilRtd è fermo: attivala dalle Impostazioni" },
    starting: { state: "busy" as const, label: "Avvio…", desc: "Collegamento al driver in corso" },
    active: {
      state: "on" as const,
      label: "Attiva",
      desc: `${nf.format(rts?.stats.exec_checked ?? 0)} esecuzioni controllate · ${nf.format(rts?.stats.exec_blocked ?? 0)} bloccate`,
    },
  }[rs];

  const modules: { name: string; desc: string; state: ModuleState; label: string }[] = [
    {
      name: "Motore Vigil",
      desc: s ? `${nf.format(s.yara_rules)} regole YARA · ${nf.format(s.hash_signatures)} hash · euristica PE` : "…",
      state: s?.engine_loading ? "busy" : "on",
      label: s?.engine_loading ? "Caricamento…" : "Attivo",
    },
    { name: "Motore ClamAV", desc: clamState[2], state: clamState[0], label: clamState[1] },
    { name: "Protezione in tempo reale", ...rtModule },
    { name: "Protezione script (AMSI)", desc: "PowerShell, VBScript, JScript: fase 5", state: "off", label: "In sviluppo" },
  ];

  const updating = s?.updating ?? false;

  return (
    <div className="page">
      <header className="page-head">
        <h1>Panoramica</h1>
      </header>

      <section className={`hero tone-${tone}`}>
        <div className="hero-stripes" aria-hidden="true">
          <i />
          <i />
          <i />
          <i />
        </div>
        <div className={`hero-ring ${scanStatus === "running" ? "spinning" : ""}`}>
          <Icon width={46} height={46} strokeWidth={1.6} />
        </div>
        <div className="hero-text">
          <div className="hero-kicker">{KICKER[tone]}</div>
          <h2>{title}</h2>
          <p>{subtitle}</p>
        </div>
        <div className="hero-actions">
          {scanStatus === "running" ? (
            <button className="btn primary" onClick={() => go("scan")}>
              Vedi avanzamento
            </button>
          ) : lastScan && detections(lastScan.summary) > 0 && tone !== "ok" ? (
            <button className={`btn ${tone === "danger" ? "danger" : "primary"}`} onClick={() => go("scan")}>
              Vedi risultati
            </button>
          ) : (
            <button className="btn primary" onClick={quick}>
              <BoltIcon width={16} height={16} /> Scansione rapida
            </button>
          )}
        </div>
      </section>

      <div className="grid-2">
        <section className="card">
          <h3 className="card-title">Moduli di protezione</h3>
          <ul className="module-list">
            {modules.map((m) => (
              <li key={m.name}>
                <span className={`dot ${m.state}`} />
                <div className="module-text">
                  <strong>{m.name}</strong>
                  <span>{m.desc}</span>
                </div>
                <span className={`pill pill-${m.state}`}>{m.label}</span>
              </li>
            ))}
          </ul>
        </section>

        <section className="card">
          <div className="card-title-row">
            <h3 className="card-title">Firme</h3>
            <button className="btn primary sm" onClick={st.update} disabled={updating}>
              <RefreshIcon width={15} height={15} className={updating ? "spin" : ""} />
              {updating ? "Aggiornamento…" : "Aggiorna firme"}
            </button>
          </div>
          {st.error && <p className="inline-error">{st.error}</p>}
          {s && (
            <>
              <dl className="stats">
                <div>
                  <dt>Regole YARA</dt>
                  <dd>{nf.format(s.yara_rules)}</dd>
                </div>
                <div>
                  <dt>Hash</dt>
                  <dd>{nf.format(s.hash_signatures)}</dd>
                </div>
                <div>
                  <dt>Aggiornate</dt>
                  <dd className="dd-small">{formatAgo(s.feeds.last_update_unix)}</dd>
                </div>
              </dl>
              <ul className="source-list">
                {(st.lastUpdateResult?.sources ?? s.feeds.sources).map((src) => (
                  <li key={src.name}>
                    <span className={`dot ${src.ok ? "on" : "warn"}`} />
                    <strong>{src.name}</strong>
                    <span className="muted">{src.message}</span>
                  </li>
                ))}
              </ul>
              <UpdateLog lines={st.updateLog} active={updating} />
              <div className="row gap-sm wrap">
                <button className="path-link" onClick={() => api.openSignaturesDir()} title="Apri la cartella delle firme personali">
                  <FolderIcon width={15} height={15} />
                  <span>Firme personali</span>
                </button>
                <button className="path-link" onClick={() => api.reloadSignatures()} disabled={s.engine_loading}>
                  <RefreshIcon width={15} height={15} className={s.engine_loading ? "spin" : ""} />
                  <span>{s.engine_loading ? "Compilazione regole…" : "Ricarica"}</span>
                </button>
              </div>
              {s.warnings.length > 0 && (
                <details className="warnings">
                  <summary>
                    {s.warnings.length} {s.warnings.length === 1 ? "avviso" : "avvisi"} durante il caricamento
                  </summary>
                  <ul>
                    {s.warnings.map((w, i) => (
                      <li key={i}>{w}</li>
                    ))}
                  </ul>
                </details>
              )}
            </>
          )}
        </section>
      </div>

      <RealtimeActivity events={rt.events} />

      <section className="card">
        <h3 className="card-title">Azioni rapide</h3>
        <div className="quick-actions">
          <button className="action" onClick={quick} disabled={scanStatus === "running"}>
            <BoltIcon />
            <span>Scansione rapida</span>
          </button>
          <button className="action" onClick={full} disabled={scanStatus === "running"}>
            <DriveIcon />
            <span>Scansione completa</span>
          </button>
          <button className="action" onClick={() => go("scan")}>
            <FolderIcon />
            <span>Scansione personalizzata</span>
          </button>
          <button className="action" onClick={() => go("settings")}>
            <SettingsIcon />
            <span>Impostazioni</span>
          </button>
        </div>
      </section>
    </div>
  );
}

function UpdateLog({ lines, active }: { lines: string[]; active: boolean }) {
  const ref = useRef<HTMLPreElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines]);
  if (lines.length === 0) return null;
  return (
    <details className="update-log" open={active}>
      <summary>Registro aggiornamento</summary>
      <pre ref={ref}>{lines.join("\n")}</pre>
    </details>
  );
}

const EVENT_LABEL: Record<RtEvent["kind"], string> = {
  blocked: "Esecuzione bloccata",
  quarantined: "Messo in quarantena",
  detected: "Minaccia rilevata",
  quarantine_failed: "Quarantena non riuscita",
};

function RealtimeActivity({ events }: { events: RtEvent[] }) {
  if (events.length === 0) return null;
  const recent = [...events].reverse().slice(0, 6);
  return (
    <section className="card card-danger">
      <h3 className="card-title">Attività in tempo reale</h3>
      <ul className="det-list">
        {recent.map((e) => (
          <li key={e.id} className={`det ${e.kind === "quarantine_failed" || e.kind === "detected" ? "det-warn" : "det-danger"}`}>
            <div className="det-head">
              <span className="threat-name">{e.threat}</span>
              <span className="pill pill-muted">{EVENT_LABEL[e.kind]}</span>
              <span className="det-time">{new Date(e.time * 1000).toLocaleString("it-IT")}</span>
            </div>
            <div className="mono det-path">{e.path}</div>
            {e.process && <div className="det-sub">da <span className="mono">{e.process}</span></div>}
            {e.detail && <div className="det-sub">{e.detail}</div>}
          </li>
        ))}
      </ul>
    </section>
  );
}
