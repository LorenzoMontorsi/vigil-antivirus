import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { errorText } from "./api";
import { BoxIcon, ShieldAlertIcon, ShieldCheckIcon, ShieldIcon, XIcon } from "./icons";
import "./Toast.css";

type Action = "quarantine" | "delete" | "exclude" | "ignore" | "open" | "close";

interface ToastData {
  id: number;
  tone: "danger" | "warn" | "ok" | "info";
  title: string;
  threat: string | null;
  path: string | null;
  process: string | null;
  message: string | null;
  actions: Action[];
  realtime: boolean;
}

const LABEL: Record<Action, string> = {
  quarantine: "Quarantena",
  delete: "Elimina",
  exclude: "Escludi",
  ignore: "Ignora",
  open: "Apri Vigil",
  close: "OK",
};

/** Contenuto di una finestra di avviso (aperta dal backend con ?toast=<id>). */
export default function ToastView({ id }: { id: number }) {
  const [data, setData] = useState<ToastData | null>(null);
  const [busy, setBusy] = useState<Action | null>(null);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    invoke<ToastData | null>("toast_get", { id }).then(setData).catch(() => {});
  }, [id]);

  if (!data) return <div className="toast toast-info" />;

  const run = async (action: Action) => {
    setBusy(action);
    setResult(null);
    try {
      const text = await invoke<string>("toast_action", { id, action });
      setResult({ ok: true, text: text || "Fatto" });
    } catch (e) {
      setResult({ ok: false, text: errorText(e) });
      setBusy(null);
    }
  };

  const Icon = data.tone === "ok" ? ShieldCheckIcon : data.tone === "info" ? ShieldIcon : ShieldAlertIcon;
  const file = data.path?.split(/[\\/]/).pop();
  const primary: Action | undefined = data.actions[0];

  return (
    <div className={`toast toast-${data.tone}`}>
      <div className="toast-stripe" />
      <div className="toast-head">
        <span className="toast-icon">
          <Icon width={20} height={20} />
        </span>
        <div className="toast-titles">
          <span className="toast-brand">Vigil{data.realtime ? " · tempo reale" : ""}</span>
          <strong>{data.title}</strong>
        </div>
        <button className="toast-x" onClick={() => invoke("toast_close", { id })} title="Chiudi" aria-label="Chiudi">
          <XIcon width={14} height={14} />
        </button>
      </div>

      <div className="toast-body">
        {data.threat && <div className="toast-threat">{data.threat}</div>}
        {file && (
          <div className="toast-file" title={data.path ?? ""}>
            <strong>{file}</strong>
            <span className="toast-path">{data.path}</span>
          </div>
        )}
        {data.process && <div className="toast-sub">da {data.process.split(/[\\/]/).pop()}</div>}
        {data.message && !result && <div className="toast-sub">{data.message}</div>}
        {result && <div className={result.ok ? "toast-ok" : "toast-err"}>{result.text}</div>}
      </div>

      {data.actions.length > 0 && !result?.ok && (
        <div className="toast-actions">
          {data.actions.map((a) => (
            <button
              key={a}
              className={`tbtn ${a === primary ? "tbtn-primary" : ""} ${a === "delete" ? "tbtn-danger" : ""}`}
              disabled={busy !== null}
              onClick={() => run(a)}
            >
              {a === "quarantine" && <BoxIcon width={13} height={13} />}
              {busy === a ? "…" : LABEL[a]}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
