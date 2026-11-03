import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { formatDuration, nf, SOURCE_LABEL, type ScanKind, type ScanResult } from "../api";
import type { ScanController } from "../useScan";
import { BoltIcon, BoxIcon, DriveIcon, FolderIcon, ShieldAlertIcon, ShieldCheckIcon } from "../icons";

const KIND_LABEL: Record<ScanKind, string> = {
  quick: "Scansione rapida",
  full: "Scansione completa",
  custom: "Scansione personalizzata",
};

export default function ScanPage({ scan }: { scan: ScanController }) {
  const { state } = scan;
  return (
    <div className="page">
      <header className="page-head">
        <h1>Scansione</h1>
      </header>
      {state.error && <div className="banner danger">{state.error}</div>}
      {state.status !== "idle" &&
        state.notes.map((n) => (
          <div className="banner warn" key={n}>
            {n}
          </div>
        ))}
      {state.status === "idle" && <Chooser scan={scan} />}
      {state.status !== "idle" && <Progress scan={scan} />}
      {state.status !== "idle" && <Threats scan={scan} />}
    </div>
  );
}

function Chooser({ scan }: { scan: ScanController }) {
  const [deep, setDeep] = useState(false);
  const custom = async () => {
    const picked = await open({ directory: true, multiple: true, title: "Scegli le cartelle da scansionare" });
    if (!picked) return;
    const paths = Array.isArray(picked) ? picked : [picked];
    if (paths.length) scan.start("custom", paths, deep);
  };
  const customFiles = async () => {
    const picked = await open({ directory: false, multiple: true, title: "Scegli i file da scansionare" });
    if (!picked) return;
    const paths = Array.isArray(picked) ? picked : [picked];
    if (paths.length) scan.start("custom", paths, deep);
  };

  return (
    <>
    <div className="scan-options">
      <button className="scan-option" onClick={() => scan.start("quick", undefined, deep)}>
        <span className="scan-option-icon">
          <BoltIcon width={26} height={26} />
        </span>
        <strong>Rapida</strong>
        <span>Desktop, Download, cartelle temporanee ed esecuzione automatica. Pochi minuti.</span>
      </button>
      <button className="scan-option" onClick={() => scan.start("full", undefined, deep)}>
        <span className="scan-option-icon">
          <DriveIcon width={26} height={26} />
        </span>
        <strong>Completa</strong>
        <span>Tutte le unità del computer. Può richiedere molto tempo.</span>
      </button>
      <div className="scan-option as-div">
        <span className="scan-option-icon">
          <FolderIcon width={26} height={26} />
        </span>
        <strong>Personalizzata</strong>
        <span>Scegli tu cartelle o singoli file.</span>
        <div className="row gap-sm">
          <button className="btn sm" onClick={custom}>
            Cartelle…
          </button>
          <button className="btn sm" onClick={customFiles}>
            File…
          </button>
        </div>
      </div>
    </div>
    <label className="deep-toggle">
      <input type="checkbox" checked={deep} onChange={(e) => setDeep(e.target.checked)} />
      <span>
        Scansione approfondita: ignora la cache e rianalizza anche i file già controllati
      </span>
    </label>
    </>
  );
}

function useNow(active: boolean) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => setNow(Date.now()), 500);
    return () => clearInterval(t);
  }, [active]);
  return now;
}

function Progress({ scan }: { scan: ScanController }) {
  const { status, kind, roots, startedAt, current, summary, handled } = scan.state;
  const autoCount = Object.values(handled).filter((h) => h.kind === "quarantined" && h.auto).length;
  const running = status === "running";
  const now = useNow(running);
  const elapsed = running && startedAt ? now - startedAt : summary.elapsed_ms;

  let title = kind ? KIND_LABEL[kind] : "Scansione";
  let Icon = null as null | typeof ShieldCheckIcon;
  let tone = "neutral";
  if (!running) {
    if (summary.infected > 0) {
      title = `Scansione completata: ${summary.infected} ${summary.infected === 1 ? "minaccia" : "minacce"}`;
      Icon = ShieldAlertIcon;
      tone = "danger";
    } else if (summary.suspicious > 0) {
      title = `Scansione completata: ${summary.suspicious} ${summary.suspicious === 1 ? "file sospetto" : "file sospetti"}`;
      Icon = ShieldAlertIcon;
      tone = "warn";
    } else if (summary.cancelled) {
      title = "Scansione interrotta";
      Icon = ShieldCheckIcon;
      tone = "warn";
    } else {
      title = "Scansione completata: nessuna minaccia";
      Icon = ShieldCheckIcon;
      tone = "ok";
    }
  }

  return (
    <section className={`card progress-card tone-${tone}`}>
      <div className="progress-head">
        <div className="row gap-sm">
          {Icon && <Icon width={26} height={26} className="tone-fg" />}
          <h2>{title}</h2>
        </div>
        {running ? (
          <button className="btn" onClick={scan.cancel}>
            Interrompi
          </button>
        ) : (
          <button className="btn primary" onClick={scan.reset}>
            Nuova scansione
          </button>
        )}
      </div>

      {running && <div className="bar indeterminate"><span /></div>}

      <dl className="stats wide">
        <div>
          <dt>File analizzati</dt>
          <dd>{nf.format(summary.scanned)}</dd>
        </div>
        <div>
          <dt>Minacce</dt>
          <dd className={summary.infected > 0 ? "fg-danger" : ""}>{nf.format(summary.infected)}</dd>
        </div>
        <div>
          <dt>Sospetti</dt>
          <dd className={summary.suspicious > 0 ? "fg-warn" : ""}>{nf.format(summary.suspicious)}</dd>
        </div>
        <div>
          <dt>Saltati</dt>
          <dd>{nf.format(summary.skipped)}</dd>
        </div>
        <div>
          <dt>Non leggibili</dt>
          <dd>{nf.format(summary.errors)}</dd>
        </div>
        <div>
          <dt>Tempo</dt>
          <dd>{formatDuration(elapsed)}</dd>
        </div>
      </dl>

      {autoCount > 0 && (
        <p className="hint ok-hint">
          {autoCount} {autoCount === 1 ? "minaccia messa" : "minacce messe"} in quarantena automaticamente
        </p>
      )}
      {(summary.cached > 0 || summary.trusted > 0) && (
        <p className="hint">
          {nf.format(summary.cached)} file già controllati (dalla cache) · {nf.format(summary.trusted)} eseguibili
          con firma Microsoft verificata
        </p>
      )}
      {running && (
        <p className="current-file" title={current}>
          {current || "Enumerazione dei file…"}
        </p>
      )}
      <details className="roots">
        <summary>{roots.length} {roots.length === 1 ? "percorso" : "percorsi"}</summary>
        <ul>
          {roots.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      </details>
    </section>
  );
}

function Threats({ scan }: { scan: ScanController }) {
  const { threats, handled, status } = scan.state;
  const [busy, setBusy] = useState(false);
  if (threats.length === 0) return null;
  const infected = threats.filter((t) => t.verdict.kind === "infected");
  const suspicious = threats.filter((t) => t.verdict.kind === "suspicious");
  const open = infected.filter((t) => !handled[t.path] || handled[t.path].kind === "failed");

  const quarantineAll = async () => {
    setBusy(true);
    await scan.quarantine(open);
    setBusy(false);
  };

  return (
    <>
      {infected.length > 0 && (
        <section className="card card-danger">
          <div className="card-title-row">
            <h3 className="card-title">Minacce rilevate</h3>
            {open.length > 0 && status !== "running" && (
              <button className="btn danger sm" onClick={quarantineAll} disabled={busy}>
                <BoxIcon width={15} height={15} />
                {busy ? "Quarantena in corso…" : `Metti tutto in quarantena (${open.length})`}
              </button>
            )}
          </div>
          <ul className="det-list">
            {infected.map((t) => (
              <Detection key={t.path} r={t} scan={scan} />
            ))}
          </ul>
        </section>
      )}
      {suspicious.length > 0 && (
        <section className="card card-warn">
          <h3 className="card-title">File sospetti</h3>
          <p className="hint">
            Segnalati dall'euristica, non da una firma: possono essere falsi positivi (per esempio programmi
            compressi con UPX). Controlla l'origine del file prima di isolarlo.
          </p>
          <ul className="det-list">
            {suspicious.map((t) => (
              <Detection key={t.path} r={t} scan={scan} />
            ))}
          </ul>
        </section>
      )}
    </>
  );
}

function Detection({ r, scan }: { r: ScanResult; scan: ScanController }) {
  const v = r.verdict;
  const h = scan.state.handled[r.path];
  const [busy, setBusy] = useState(false);
  const done = h && h.kind !== "failed";

  const actions = (
    <div className="det-actions">
      {h?.kind === "quarantined" && (
        <span className="pill pill-on">
          <BoxIcon width={13} height={13} /> In quarantena
        </span>
      )}
      {h?.kind === "ignored" && <span className="pill pill-muted">Ignorato</span>}
      {!done && (
        <>
          <button
            className={`btn sm ${v.kind === "infected" ? "danger" : ""}`}
            disabled={busy || scan.state.status === "running"}
            onClick={async () => {
              setBusy(true);
              await scan.quarantine([r]);
              setBusy(false);
            }}
          >
            <BoxIcon width={14} height={14} /> {busy ? "…" : "Quarantena"}
          </button>
          <button className="btn ghost sm" onClick={() => scan.ignore(r.path)}>
            Ignora
          </button>
        </>
      )}
    </div>
  );

  if (v.kind === "infected") {
    return (
      <li className={`det det-danger ${done ? "det-done" : ""}`}>
        <div className="det-head">
          <span className="threat-name">{v.threat}</span>
          <span className="pill pill-muted">{SOURCE_LABEL[v.source]}</span>
          {actions}
        </div>
        <div className="mono det-path">{r.path}</div>
        {v.location && <div className="det-sub">dentro l'archivio: <span className="mono">{v.location}</span></div>}
        {v.description && <div className="det-sub">{v.description}</div>}
        {r.sha256 && <div className="det-sub mono">SHA-256 {r.sha256}</div>}
        {h?.kind === "failed" && <div className="inline-error">Quarantena non riuscita: {h.error}</div>}
      </li>
    );
  }
  if (v.kind === "suspicious") {
    return (
      <li className={`det det-warn ${done ? "det-done" : ""}`}>
        <div className="det-head">
          <span className="suspect-name">Sospetto</span>
          <span className="pill pill-warn">punteggio {v.score}</span>
          {actions}
        </div>
        <div className="mono det-path">{r.path}</div>
        <ul className="reasons">
          {v.reasons.map((x) => (
            <li key={x}>{x}</li>
          ))}
        </ul>
        {h?.kind === "failed" && <div className="inline-error">Quarantena non riuscita: {h.error}</div>}
      </li>
    );
  }
  return null;
}
