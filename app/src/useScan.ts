import { useCallback, useEffect, useState } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { api, errorText, quarantineRequest, type ScanKind, type ScanResult, type ScanSummary } from "./api";

export type ScanStatus = "idle" | "running" | "done";

export interface LastScan {
  kind: ScanKind;
  finishedAt: Date;
  summary: ScanSummary;
}

/** Cosa è stato fatto di un rilevamento. */
export type Handled = { kind: "quarantined"; auto?: boolean } | { kind: "ignored" } | { kind: "failed"; error: string };

export interface ScanState {
  status: ScanStatus;
  kind: ScanKind | null;
  roots: string[];
  startedAt: number | null;
  current: string;
  summary: ScanSummary;
  threats: ScanResult[];
  lastScan: LastScan | null;
  notes: string[];
  handled: Record<string, Handled>;
  error: string | null;
}

const emptySummary: ScanSummary = {
  scanned: 0,
  infected: 0,
  suspicious: 0,
  skipped: 0,
  errors: 0,
  cached: 0,
  trusted: 0,
  cancelled: false,
  elapsed_ms: 0,
};

const initial: ScanState = {
  status: "idle",
  kind: null,
  roots: [],
  startedAt: null,
  current: "",
  summary: emptySummary,
  threats: [],
  lastScan: null,
  notes: [],
  handled: {},
  error: null,
};

export function useScan() {
  const [state, setState] = useState<ScanState>(initial);

  useEffect(() => {
    let disposed = false;
    const unlisteners: UnlistenFn[] = [];
    const on = async <T,>(event: string, handler: (payload: T) => void) => {
      const un = await listen<T>(event, (e) => handler(e.payload));
      if (disposed) un();
      else unlisteners.push(un);
    };

    on<{ kind: ScanKind; roots: string[]; notes: string[] }>("scan://started", ({ kind, roots, notes }) =>
      setState((s) => ({
        ...s,
        status: "running",
        kind,
        roots,
        notes,
        startedAt: Date.now(),
        current: "",
        summary: emptySummary,
        threats: [],
        handled: {},
        error: null,
      })),
    );
    on<{ summary: ScanSummary; current: string }>("scan://progress", ({ summary, current }) =>
      setState((s) => ({ ...s, summary, current })),
    );
    on<ScanResult>("scan://threat", (r) => setState((s) => ({ ...s, threats: [...s.threats, r] })));
    on<{ path: string; ok: boolean; error: string | null }>("scan://handled", (h) =>
      setState((s) => ({
        ...s,
        handled: {
          ...s.handled,
          [h.path]: h.ok ? { kind: "quarantined", auto: true } : { kind: "failed", error: h.error ?? "errore sconosciuto" },
        },
      })),
    );
    on<ScanSummary>("scan://finished", (summary) =>
      setState((s) => ({
        ...s,
        status: "done",
        summary,
        current: "",
        lastScan: { kind: s.kind ?? "custom", finishedAt: new Date(), summary },
      })),
    );

    return () => {
      disposed = true;
      unlisteners.forEach((un) => un());
    };
  }, []);

  const start = useCallback(async (kind: ScanKind, paths?: string[], ignoreCache = false) => {
    try {
      await api.startScan(kind, paths, ignoreCache);
    } catch (e) {
      setState((s) => ({ ...s, error: errorText(e) }));
    }
  }, []);

  const cancel = useCallback(() => api.cancelScan(), []);

  /** Mette in quarantena i risultati indicati e ne registra l'esito. */
  const quarantine = useCallback(async (results: ScanResult[]) => {
    const reqs = results.map(quarantineRequest).filter((r): r is NonNullable<typeof r> => r !== null);
    if (reqs.length === 0) return;
    try {
      const outcomes = await api.quarantineAdd(reqs);
      setState((s) => {
        const handled = { ...s.handled };
        for (const o of outcomes) {
          handled[o.path] = o.ok ? { kind: "quarantined" } : { kind: "failed", error: o.error ?? "errore sconosciuto" };
        }
        return { ...s, handled };
      });
    } catch (e) {
      setState((s) => ({ ...s, error: errorText(e) }));
    }
  }, []);

  const ignore = useCallback(
    (path: string) => setState((s) => ({ ...s, handled: { ...s.handled, [path]: { kind: "ignored" } } })),
    [],
  );
  const reset = useCallback(
    () => setState((s) => (s.status === "running" ? s : { ...s, status: "idle", threats: [], error: null })),
    [],
  );

  return { state, start, cancel, reset, quarantine, ignore };
}

export type ScanController = ReturnType<typeof useScan>;
