import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { openUrl } from "@tauri-apps/plugin-opener";
import { api, errorText, nf, rtState, type RulesPackage, type Settings } from "../api";
import type { StatusController } from "../useStatus";
import type { RealtimeController } from "../useRealtime";
import { FileIcon, FolderIcon, XIcon } from "../icons";

export default function SettingsPage({ status, rt }: { status: StatusController; rt: RealtimeController }) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [ext, setExt] = useState("");
  const [mbKey, setMbKey] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api
      .getSettings()
      .then((s) => {
        setSettings(s);
        setMbKey(s.malwarebazaar_key);
      })
      .catch((e) => setErr(errorText(e)));
  }, []);

  const save = async (next: Settings) => {
    setSettings(next);
    try {
      await api.saveSettings(next);
      setErr(null);
      setSaved(true);
      setTimeout(() => setSaved(false), 1500);
    } catch (e) {
      setErr(errorText(e));
    }
  };

  if (!settings) {
    return (
      <div className="page">
        <header className="page-head">
          <h1>Impostazioni</h1>
        </header>
        {err && <div className="banner danger">{err}</div>}
      </div>
    );
  }

  const set = <K extends keyof Settings>(k: K, v: Settings[K]) => save({ ...settings, [k]: v });
  const { exclusions } = settings;

  const addPaths = async (directory: boolean) => {
    const picked = await open({ directory, multiple: true, title: "Aggiungi esclusione" });
    if (!picked) return;
    const list = (Array.isArray(picked) ? picked : [picked]).filter(
      (p) => !exclusions.paths.some((x) => x.toLowerCase() === p.toLowerCase()),
    );
    if (list.length) set("exclusions", { ...exclusions, paths: [...exclusions.paths, ...list] });
  };
  const removePath = (p: string) => set("exclusions", { ...exclusions, paths: exclusions.paths.filter((x) => x !== p) });

  const addExt = (e: FormEvent) => {
    e.preventDefault();
    const clean = ext.trim().replace(/^\.+/, "").toLowerCase();
    if (!clean || !/^[a-z0-9_-]+$/.test(clean)) {
      setErr("Estensione non valida: usa solo lettere, numeri, - e _ (es. iso)");
      return;
    }
    setExt("");
    if (exclusions.extensions.includes(clean)) return;
    set("exclusions", { ...exclusions, extensions: [...exclusions.extensions, clean] });
  };
  const removeExt = (x: string) =>
    set("exclusions", { ...exclusions, extensions: exclusions.extensions.filter((e) => e !== x) });

  const clam = status.status?.clamav;

  return (
    <div className="page">
      <header className="page-head">
        <h1>Impostazioni</h1>
        {saved && <span className="saved">Salvato</span>}
      </header>
      {err && <div className="banner danger">{err}</div>}

      <RealtimeSection rt={rt} />

      <section className="card">
        <h3 className="card-title">Rilevamento</h3>
        <Toggle
          checked={settings.heuristics}
          onChange={(v) => set("heuristics", v)}
          title="Euristica"
          desc="Segnala come sospetti eseguibili compressi o offuscati, import tipici di iniezione e keylogger, doppie estensioni ingannevoli."
        />
        <Toggle
          checked={settings.auto_quarantine}
          onChange={(v) => set("auto_quarantine", v)}
          title="Quarantena automatica"
          desc="Isola subito le minacce certe trovate da hash, YARA o ClamAV. I file solo sospetti restano da decidere a te. Puoi sempre ripristinare dalla pagina Quarantena."
        />
        <Toggle
          checked={settings.trust_microsoft}
          onChange={(v) => set("trust_microsoft", v)}
          title="Fidati dei file firmati da Microsoft"
          desc="Gli eseguibili con firma Microsoft verificata (anche tramite catalogo di sistema) saltano ClamAV, euristica e regole a bassa affidabilità. Molto più veloce, e niente falsi positivi sui file di Windows."
        />
        <Toggle
          checked={settings.use_cache}
          onChange={(v) => set("use_cache", v)}
          title="Cache delle scansioni"
          desc="Non rianalizza i file già trovati puliti e non più modificati. La cache si azzera da sola quando cambiano le firme."
        />
        <div className="row gap-sm">
          <span className="muted">
            {status.status ? `${status.status.cache_entries.toLocaleString("it-IT")} file in cache` : ""}
          </span>
          <button
            className="btn sm"
            onClick={() => api.clearCache().then(status.refresh).catch((e) => setErr(errorText(e)))}
          >
            Svuota cache
          </button>
        </div>
        <Toggle
          checked={settings.scan_archives}
          onChange={(v) => set("scan_archives", v)}
          title="Analizza gli archivi ZIP"
          desc="Apre gli ZIP (anche annidati, fino a 3 livelli) con limiti contro le zip-bomb."
        />
        <label className="field">
          <span>Dimensione massima dei file da analizzare</span>
          <div className="row gap-sm">
            <input
              className="input narrow"
              type="number"
              min={1}
              max={4096}
              value={settings.max_file_size_mb}
              onChange={(e) => setSettings({ ...settings, max_file_size_mb: Number(e.target.value) || 1 })}
              onBlur={() => save(settings)}
            />
            <span className="muted">MB</span>
          </div>
        </label>
      </section>

      <section className="card">
        <h3 className="card-title">Fonti delle firme</h3>
        <label className="field">
          <span>Regole YARA-Forge</span>
          <select
            className="input"
            value={settings.rules_package}
            onChange={(e) => set("rules_package", e.target.value as RulesPackage)}
          >
            <option value="core">Core: circa 5.000 regole, pochissimi falsi positivi (consigliato)</option>
            <option value="extended">Extended: circa 11.000 regole, più copertura</option>
            <option value="none">Nessuna</option>
          </select>
        </label>
        <label className="field">
          <span>
            Auth-Key di MalwareBazaar{" "}
            <button className="link" type="button" onClick={() => openUrl("https://auth.abuse.ch/")}>
              (ottienila gratis)
            </button>
          </span>
          <div className="row gap-sm">
            <input
              className="input wide"
              type="password"
              placeholder="vuoto = disattivato"
              value={mbKey}
              onChange={(e) => setMbKey(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
            <button className="btn" disabled={mbKey === settings.malwarebazaar_key} onClick={() => set("malwarebazaar_key", mbKey.trim())}>
              Salva chiave
            </button>
          </div>
          <span className="hint">
            A ogni aggiornamento scarica gli hash dei campioni delle ultime 48 ore e li aggiunge all'archivio locale.
          </span>
        </label>
        <Toggle
          checked={settings.auto_update}
          onChange={(v) => set("auto_update", v)}
          title="Aggiornamento automatico"
          desc="All'avvio, se le firme hanno più di 24 ore."
        />
        <div className="row gap-sm">
          <button className="btn primary" onClick={status.update} disabled={status.status?.updating}>
            {status.status?.updating ? "Aggiornamento in corso…" : "Aggiorna ora"}
          </button>
        </div>
      </section>

      <section className="card">
        <div className="card-title-row">
          <h3 className="card-title">Motore ClamAV</h3>
          {clam && settings.clamav_enabled && (
            <span className={`pill ${clam.running ? "pill-on" : clam.starting ? "pill-busy" : "pill-warn"}`}>
              {clam.running ? "Attivo" : clam.starting ? "Avvio…" : "Fermo"}
            </span>
          )}
        </div>
        <Toggle
          checked={settings.clamav_enabled}
          onChange={(v) => set("clamav_enabled", v)}
          title="Usa ClamAV come secondo motore"
          desc="Circa 3,6 milioni di firme, decompressione di RAR, 7z, CAB e degli eseguibili compressi. Il servizio clamd occupa circa 1–1,5 GB di RAM mentre Vigil è aperto."
        />
        <p className="hint">
          {clam?.installed
            ? `Incluso in Vigil: ClamAV ${clam.bundled_version ?? ""} (Cisco Talos, licenza GPL v2).`
            : "ClamAV non è ancora presente: Vigil lo scarica da solo (circa 225 MB, SHA-256 verificato) con il prossimo aggiornamento delle firme. Puoi avviarlo subito con «Aggiorna ora»."}
        </p>
        {clam && settings.clamav_enabled && (
          <>
            {!clam.database && <p className="hint">Firme non ancora scaricate: premi “Aggiorna ora”.</p>}
            {clam.version && <p className="hint mono">{clam.version}</p>}
            {status.clamavError && !clam.running && <p className="inline-error">{status.clamavError}</p>}
            {!clam.running && !clam.starting && clam.database && clam.installed && (
              <div>
                <button className="btn sm" onClick={() => api.startClamav().then(status.refresh)}>
                  Avvia ClamAV
                </button>
              </div>
            )}
          </>
        )}
      </section>

      <section className="card">
        <div className="card-title-row">
          <h3 className="card-title">Cartelle e file esclusi</h3>
          <div className="row gap-sm">
            <button className="btn sm" onClick={() => addPaths(true)}>
              <FolderIcon width={15} height={15} /> Cartella
            </button>
            <button className="btn sm" onClick={() => addPaths(false)}>
              <FileIcon width={15} height={15} /> File
            </button>
          </div>
        </div>
        <p className="hint">
          Gli elementi esclusi non vengono mai analizzati. Ogni esclusione è un punto cieco: aggiungi solo percorsi di
          cui ti fidi.
        </p>
        {exclusions.paths.length === 0 ? (
          <p className="muted">Nessuna esclusione.</p>
        ) : (
          <ul className="excl-list">
            {exclusions.paths.map((p) => (
              <li key={p}>
                <span className="mono">{p}</span>
                <button className="icon-btn" onClick={() => removePath(p)} title="Rimuovi">
                  <XIcon width={16} height={16} />
                </button>
              </li>
            ))}
          </ul>
        )}
        <form className="row gap-sm" onSubmit={addExt}>
          <input
            className="input"
            placeholder="estensione, es. iso"
            value={ext}
            onChange={(e) => setExt(e.target.value)}
            aria-label="Estensione da escludere"
          />
          <button className="btn" type="submit">
            Escludi estensione
          </button>
        </form>
        {exclusions.extensions.length > 0 && (
          <div className="chips">
            {exclusions.extensions.map((x) => (
              <span className="chip" key={x}>
                .{x}
                <button onClick={() => removeExt(x)} title="Rimuovi" aria-label={`Rimuovi .${x}`}>
                  <XIcon width={13} height={13} />
                </button>
              </span>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function Toggle(props: { checked: boolean; onChange: (v: boolean) => void; title: string; desc: ReactNode }) {
  return (
    <label className="toggle-row">
      <div className="toggle-text">
        <strong>{props.title}</strong>
        <span>{props.desc}</span>
      </div>
      <input
        type="checkbox"
        className="switch"
        checked={props.checked}
        onChange={(e) => props.onChange(e.target.checked)}
      />
    </label>
  );
}

function RealtimeSection({ rt }: { rt: RealtimeController }) {
  const state = rtState(rt.status);
  const st = rt.status?.status;
  const label = { not_installed: "Non installata", stopped: "Disattivata", starting: "Avvio…", active: "Attiva", paused: "Sospesa" }[state];
  const pill = { not_installed: "pill-off", stopped: "pill-warn", starting: "pill-busy", active: "pill-on", paused: "pill-warn" }[state];
  const on = state === "active" || state === "starting" || state === "paused";
  return (
    <section className="card">
      <div className="card-title-row">
        <h3 className="card-title">Protezione in tempo reale</h3>
        <span className={`pill ${pill}`}>{label}</span>
      </div>
      {state === "not_installed" ? (
        <p className="hint">
          Il servizio VigilRtd e il driver VigilFlt non sono installati su questo PC. Per ora funzionano solo in una
          macchina virtuale di test con la firma dei driver in modalità test: per un PC normale serve un driver firmato
          da Microsoft.
        </p>
      ) : (
        <>
          <label className="toggle-row">
            <div className="toggle-text">
              <strong>Blocca le minacce in tempo reale</strong>
              <span>
                Controlla ogni programma prima che parta e ogni file appena scritto. Per attivarla o disattivarla
                Windows chiede l'autorizzazione di amministratore: un malware non può spegnerla da solo.
              </span>
            </div>
            <input
              type="checkbox"
              className="switch"
              checked={on}
              disabled={rt.busy}
              onChange={(e) => rt.setEnabled(e.target.checked)}
            />
          </label>
          {rt.busy && <p className="hint">In attesa della conferma di Windows…</p>}
          {rt.error && <p className="inline-error">{rt.error}</p>}
          {st && (
            <dl className="stats">
              <div>
                <dt>Esecuzioni controllate</dt>
                <dd>{nf.format(st.stats.exec_checked)}</dd>
              </div>
              <div>
                <dt>Bloccate</dt>
                <dd className={st.stats.exec_blocked > 0 ? "fg-danger" : ""}>{nf.format(st.stats.exec_blocked)}</dd>
              </div>
              <div>
                <dt>File scritti isolati</dt>
                <dd>{nf.format(st.stats.quarantined)}</dd>
              </div>
            </dl>
          )}
          {st && (
            <p className="hint">
              Servizio v{st.version} · {nf.format(st.yara_rules)} regole YARA · quarantena automatica dei file scritti{" "}
              {st.auto_quarantine ? "attiva" : "disattivata"}
            </p>
          )}
        </>
      )}
    </section>
  );
}
