import { useCallback, useEffect, useState } from "react";
import { ask } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import { api, errorText, formatSize, rtApi, type QuarantineItem } from "../api";
import { BoxIcon, RefreshIcon, XIcon } from "../icons";

const SOURCE: Record<string, string> = {
  yara: "YARA",
  clamav: "ClamAV",
  hash: "Hash",
  heuristics: "Euristica",
};

export default function Quarantine() {
  const [items, setItems] = useState<QuarantineItem[] | null>(null);
  const [serviceItems, setServiceItems] = useState<QuarantineItem[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(() => {
    rtApi.vaultList().then(setServiceItems).catch(() => {});
    api
      .quarantineList()
      .then((l) => {
        setItems(l);
        setErr(null);
      })
      .catch((e) => setErr(errorText(e)));
  }, []);

  useEffect(() => {
    load();
    let un: (() => void) | undefined;
    let disposed = false;
    listen("quarantine://changed", load).then((u) => (disposed ? u() : (un = u)));
    return () => {
      disposed = true;
      un?.();
    };
  }, [load]);

  const run = async (id: string, fn: () => Promise<unknown>, ok?: string) => {
    setBusy(id);
    setInfo(null);
    try {
      await fn();
      setErr(null);
      if (ok) setInfo(ok);
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(null);
      load();
    }
  };

  const restore = async (it: QuarantineItem, exclude: boolean) => {
    const yes = await ask(
      `Il file verrà rimesso in:\n${it.original_path}\n\nÈ stato rilevato come "${it.threat}". Ripristinalo solo se sei sicuro che sia un falso positivo.` +
        (exclude ? "\n\nVerrà anche aggiunto alle esclusioni: le prossime scansioni lo ignoreranno." : ""),
      { title: "Ripristinare il file?", kind: "warning", okLabel: "Ripristina", cancelLabel: "Annulla" },
    );
    if (yes) {
      await run(it.id, () => api.quarantineRestore(it.id, exclude), `Ripristinato: ${it.original_path}`);
    }
  };

  const remove = async (it: QuarantineItem) => {
    const yes = await ask(`Eliminare definitivamente "${it.threat}"?\n${it.original_path}`, {
      title: "Eliminare dalla quarantena?",
      kind: "warning",
      okLabel: "Elimina",
      cancelLabel: "Annulla",
    });
    if (yes) await run(it.id, () => api.quarantineDelete([it.id]));
  };

  const removeAll = async () => {
    if (!items?.length) return;
    const yes = await ask(`Eliminare definitivamente tutti i ${items.length} file in quarantena?`, {
      title: "Svuotare la quarantena?",
      kind: "warning",
      okLabel: "Svuota",
      cancelLabel: "Annulla",
    });
    if (yes) await run("*", () => api.quarantineDelete(items.map((i) => i.id)));
  };

  const totalSize = items?.reduce((n, i) => n + i.size, 0) ?? 0;

  return (
    <div className="page">
      <header className="page-head">
        <h1>Quarantena</h1>
        {items && items.length > 0 && (
          <button className="btn sm" onClick={removeAll} disabled={busy !== null}>
            <XIcon width={14} height={14} /> Svuota quarantena
          </button>
        )}
      </header>
      {err && <div className="banner danger">{err}</div>}
      {info && <div className="banner ok">{info}</div>}

      {items && items.length === 0 && serviceItems.length === 0 && (
        <section className="card empty">
          <BoxIcon width={44} height={44} strokeWidth={1.4} />
          <h2>La quarantena è vuota</h2>
          <p>
            I file isolati finiscono qui cifrati: non possono essere eseguiti né fare danni. Da qui puoi ripristinarli,
            se erano falsi positivi, o eliminarli per sempre.
          </p>
        </section>
      )}

      {items && items.length > 0 && (
        <section className="card card-violet">
          <div className="card-title-row">
            <h3 className="card-title">
              {items.length} {items.length === 1 ? "file isolato" : "file isolati"} · {formatSize(totalSize)}
            </h3>
          </div>
          <ul className="det-list">
            {items.map((it) => (
              <li key={it.id} className={`det det-vault ${busy === it.id || busy === "*" ? "det-done" : ""}`}>
                <div className="det-head">
                  <span className="threat-name">{it.threat}</span>
                  <span className="pill pill-muted">{SOURCE[it.source] ?? it.source}</span>
                  <div className="det-actions">
                    <button className="btn ghost sm" disabled={busy !== null} onClick={() => restore(it, false)}>
                      <RefreshIcon width={14} height={14} /> Ripristina
                    </button>
                    <button className="btn ghost sm" disabled={busy !== null} onClick={() => restore(it, true)}>
                      Ripristina ed escludi
                    </button>
                    <button className="btn sm danger" disabled={busy !== null} onClick={() => remove(it)}>
                      <XIcon width={14} height={14} /> Elimina
                    </button>
                  </div>
                </div>
                <div className="mono det-path">{it.original_path}</div>
                <div className="det-sub">
                  {new Date(it.quarantined_at * 1000).toLocaleString("it-IT")} · {formatSize(it.size)} ·{" "}
                  <span className="mono">SHA-256 {it.sha256.slice(0, 16)}…</span>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {serviceItems.length > 0 && <ServiceVault items={serviceItems} reload={load} />}
    </div>
  );
}

/** File isolati dal servizio di protezione in tempo reale: il deposito è protetto,
 *  quindi ripristino ed eliminazione chiedono l'autorizzazione di Windows. */
function ServiceVault({ items, reload }: { items: QuarantineItem[]; reload: () => void }) {
  const [err, setErr] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);

  // Le operazioni partono in un processo con privilegi: ricarichiamo dopo qualche secondo.
  useEffect(() => {
    if (!pending) return;
    const t = setInterval(reload, 2000);
    const stop = setTimeout(() => setPending(null), 20000);
    return () => {
      clearInterval(t);
      clearTimeout(stop);
    };
  }, [pending, reload]);
  useEffect(() => {
    if (pending && !items.some((i) => i.id === pending)) setPending(null);
  }, [items, pending]);

  const run = async (id: string, fn: () => Promise<void>) => {
    setErr(null);
    try {
      await fn();
      setPending(id);
    } catch (e) {
      setErr(errorText(e));
    }
  };

  const restore = async (it: QuarantineItem, exclude: boolean) => {
    const yes = await ask(
      `Il file verrà rimesso in:\n${it.original_path}\n\nÈ stato rilevato come "${it.threat}" dalla protezione in tempo reale.` +
        (exclude ? "\n\nVerrà anche escluso dalla protezione: non sarà più controllato." : "") +
        "\n\nWindows chiederà l'autorizzazione di amministratore.",
      { title: "Ripristinare il file?", kind: "warning", okLabel: "Ripristina", cancelLabel: "Annulla" },
    );
    if (yes) run(it.id, () => rtApi.vaultRestore(it.id, exclude));
  };

  const remove = async (it: QuarantineItem) => {
    const yes = await ask(`Eliminare definitivamente "${it.threat}"?\n${it.original_path}`, {
      title: "Eliminare dalla quarantena?",
      kind: "warning",
      okLabel: "Elimina",
      cancelLabel: "Annulla",
    });
    if (yes) run(it.id, () => rtApi.vaultDelete([it.id]));
  };

  return (
    <section className="card card-danger">
      <div className="card-title-row">
        <h3 className="card-title">
          Isolati dalla protezione in tempo reale · {items.length} {items.length === 1 ? "file" : "file"}
        </h3>
      </div>
      <p className="hint">
        Messi in quarantena dal servizio appena scritti sul disco. Per ripristinarli o eliminarli Windows chiede
        l'autorizzazione di amministratore.
      </p>
      {err && <p className="inline-error">{err}</p>}
      <ul className="det-list">
        {items.map((it) => (
          <li key={it.id} className={`det det-vault ${pending === it.id ? "det-done" : ""}`}>
            <div className="det-head">
              <span className="threat-name">{it.threat}</span>
              <span className="pill pill-muted">{SOURCE[it.source] ?? it.source}</span>
              <div className="det-actions">
                <button className="btn ghost sm" disabled={pending !== null} onClick={() => restore(it, false)}>
                  <RefreshIcon width={14} height={14} /> Ripristina
                </button>
                <button className="btn ghost sm" disabled={pending !== null} onClick={() => restore(it, true)}>
                  Ripristina ed escludi
                </button>
                <button className="btn sm danger" disabled={pending !== null} onClick={() => remove(it)}>
                  <XIcon width={14} height={14} /> Elimina
                </button>
              </div>
            </div>
            <div className="mono det-path">{it.original_path}</div>
            <div className="det-sub">
              {new Date(it.quarantined_at * 1000).toLocaleString("it-IT")} · {formatSize(it.size)} ·{" "}
              <span className="mono">SHA-256 {it.sha256.slice(0, 16)}…</span>
              {pending === it.id && " · in attesa della conferma di Windows…"}
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
