import { useCallback, useEffect, useState } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { errorText, rtApi, type RtEvent, type RtUiStatus } from "./api";

export interface RealtimeController {
  status: RtUiStatus | null;
  events: RtEvent[];
  error: string | null;
  busy: boolean;
  setEnabled: (enabled: boolean) => Promise<void>;
}

/** Stato del servizio di protezione in tempo reale, aggiornato dagli eventi del backend. */
export function useRealtime(): RealtimeController {
  const [status, setStatus] = useState<RtUiStatus | null>(null);
  const [events, setEvents] = useState<RtEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    rtApi.status().then(setStatus).catch(() => {});
    rtApi.events().then(setEvents).catch(() => {});
    let disposed = false;
    const uns: UnlistenFn[] = [];
    const on = async <T,>(ev: string, h: (p: T) => void) => {
      const un = await listen<T>(ev, (e) => h(e.payload));
      if (disposed) un();
      else uns.push(un);
    };
    on<RtUiStatus>("rt://status", (s) => {
      setStatus(s);
      setBusy(false);
    });
    on<RtEvent>("rt://event", (e) =>
      setEvents((list) => (list.some((x) => x.id === e.id) ? list : [...list.slice(-99), e])),
    );
    return () => {
      disposed = true;
      uns.forEach((u) => u());
    };
  }, []);

  const setEnabled = useCallback(async (enabled: boolean) => {
    setError(null);
    setBusy(true);
    try {
      await rtApi.setEnabled(enabled);
      // Lo stato vero arriva con il prossimo "rt://status"; se non cambia nulla, sblocca dopo un po'.
      setTimeout(() => setBusy(false), 15000);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  }, []);

  return { status, events, error, busy, setEnabled };
}
