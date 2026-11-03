import { useCallback, useEffect, useState } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { api, errorText, type SourceStatus, type Status } from "./api";

export interface StatusController {
  status: Status | null;
  error: string | null;
  updateLog: string[];
  lastUpdateResult: { ok: boolean; sources: SourceStatus[] } | null;
  clamavError: string | null;
  refresh: () => void;
  update: () => Promise<void>;
}

/** Stato globale di motore, firme e ClamAV, aggiornato dagli eventi del backend. */
export function useStatus(): StatusController {
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [updateLog, setUpdateLog] = useState<string[]>([]);
  const [lastUpdateResult, setLastUpdateResult] = useState<StatusController["lastUpdateResult"]>(null);
  const [clamavError, setClamavError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    api
      .status()
      .then((s) => {
        setStatus(s);
        setError(null);
        if (s.clamav.running) setClamavError(null);
      })
      .catch((e) => setError(errorText(e)));
  }, []);

  useEffect(() => {
    refresh();
    let disposed = false;
    const uns: UnlistenFn[] = [];
    const on = async <T,>(ev: string, h: (p: T) => void) => {
      const un = await listen<T>(ev, (e) => h(e.payload));
      if (disposed) un();
      else uns.push(un);
    };
    on("status://changed", () => refresh());
    on("quarantine://changed", () => refresh());
    on<string>("update://log", (line) => setUpdateLog((l) => [...l.slice(-200), line]));
    on<{ ok: boolean; sources: SourceStatus[] }>("update://done", (r) => {
      setLastUpdateResult(r);
      refresh();
    });
    on<string>("clamav://error", (e) => setClamavError(e));
    // Lo stato di clamd cambia anche da solo (avvio lento): ricontrolla ogni tanto.
    const t = setInterval(refresh, 5000);
    return () => {
      disposed = true;
      clearInterval(t);
      uns.forEach((u) => u());
    };
  }, [refresh]);

  const update = useCallback(async () => {
    setUpdateLog([]);
    setLastUpdateResult(null);
    try {
      await api.updateSignatures();
      refresh();
    } catch (e) {
      setError(errorText(e));
    }
  }, [refresh]);

  return { status, error, updateLog, lastUpdateResult, clamavError, refresh, update };
}
