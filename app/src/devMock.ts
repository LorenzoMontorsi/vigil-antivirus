// Finto backend per vedere l'interfaccia nel browser (solo `npm run dev`,
// fuori da Tauri). Non finisce mai nella build di produzione.

import type { Settings, Status } from "./api";

const status: Status = {
  version: "0.1.0",
  yara_rules: 5135,
  hash_signatures: 923,
  warnings: [],
  engine_loading: false,
  updating: false,
  signatures_dir: "C:\\Users\\demo\\AppData\\Roaming\\dev.lorenzo.antivirus\\signatures",
  feeds: {
    last_update_unix: Math.floor(Date.now() / 1000) - 3600,
    yara_forge_release: "20261101",
    malwarebazaar_hashes: 923,
    sources: [
      { name: "YARA-Forge", ok: true, message: "pacchetto core, release 20261101" },
      { name: "MalwareBazaar", ok: true, message: "923 nuovi hash, 923 in totale" },
      { name: "ClamAV", ok: true, message: "daily.cvd database is up-to-date (version: 28172)" },
    ],
  },
  clamav_enabled: true,
  clamav: {
    installed: true,
    bundled_version: "1.5.4",
    database: true,
    running: true,
    starting: false,
    version: "ClamAV 1.5.4/28172/Mon Nov  2 07:24:10 2026",
  },
  cache_entries: 20651,
  quarantine_count: 2,
};

const settings: Settings = {
  exclusions: { paths: ["D:\\Progetti\\build"], extensions: ["iso"] },
  max_file_size_mb: 64,
  heuristics: true,
  scan_archives: true,
  trust_microsoft: true,
  use_cache: true,
  auto_quarantine: true,
  rules_package: "core",
  malwarebazaar_key: "",
  auto_update: true,
  clamav_enabled: true,
};

const vault = [
  {
    id: "1793650000-a1b2c3d4e5f6",
    original_path: "C:\\Users\\demo\\Downloads\\crack_photoshop.zip",
    threat: "Win.Trojan.Agent-1234567",
    source: "clamav",
    sha256: "9f2c7a1e0b3d4c5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6",
    size: 812331,
    quarantined_at: Math.floor(Date.now() / 1000) - 600,
  },
  {
    id: "1793640000-0f1e2d3c4b5a",
    original_path: "C:\\Users\\demo\\AppData\\Local\\Temp\\upd4te.exe",
    threat: "MalwareBazaar.AgentTesla",
    source: "hash",
    sha256: "27b5c0a3f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
    size: 233472,
    quarantined_at: Math.floor(Date.now() / 1000) - 86400 * 2,
  },
];

export function installDevMock() {
  const w = window as unknown as Record<string, unknown>;
  if (w.__TAURI_INTERNALS__) return;
  let id = 0;
  const callbacks = new Map<number, (e: unknown) => void>();
  const listeners = new Map<string, number[]>();
  const emit = (event: string, payload: unknown) =>
    (listeners.get(event) ?? []).forEach((h) => callbacks.get(h)?.({ event, id: 0, payload }));

  const unregister = (event: string, eventId: number) =>
    listeners.set(event, (listeners.get(event) ?? []).filter((h) => h !== eventId));
  w.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: unregister };

  w.__TAURI_INTERNALS__ = {
    transformCallback: (cb: (e: unknown) => void) => {
      callbacks.set(++id, cb);
      return id;
    },
    invoke: async (cmd: string, args: Record<string, unknown> = {}) => {
      switch (cmd) {
        case "status":
          return status;
        case "get_settings":
          return settings;
        case "quarantine_list":
          return new URLSearchParams(location.search).get("demo") === "vault" ? vault : [];
        case "quarantine_add":
          return (args.items as { path: string }[]).map((i) => ({ path: i.path, ok: !i.path.includes("Fattura"), error: i.path.includes("Fattura") ? "il file è in uso: chiudi il programma che lo usa e riprova" : null }));
        case "plugin:event|listen": {
          const ev = args.event as string;
          listeners.set(ev, [...(listeners.get(ev) ?? []), args.handler as number]);
          return args.handler;
        }
        case "plugin:event|unlisten":
          unregister(args.event as string, args.eventId as number);
          return null;
        default:
          return null;
      }
    },
  };

  // ?demo=threats: simula una scansione conclusa con rilevamenti.
  if (new URLSearchParams(location.search).get("demo") === "threats") {
    const summary = {
      scanned: 1842, infected: 2, suspicious: 1, skipped: 3, errors: 12, cached: 1210, trusted: 388,
      cancelled: false, elapsed_ms: 47000,
    };
    setTimeout(() => {
      emit("scan://started", { kind: "quick", roots: ["C:\\Users\\demo\\Downloads"], notes: [] });
      emit("scan://threat", {
        path: "C:\\Users\\demo\\Downloads\\crack_photoshop.zip", size: 812331, sha256: "9f2c…e1",
        verdict: { kind: "infected", threat: "Win.Trojan.Agent-1234567", source: "clamav", description: null, location: "setup/keygen.exe" },
      });
      emit("scan://threat", {
        path: "C:\\Users\\demo\\Downloads\\eicar.com", size: 68, sha256: "275a…0f",
        verdict: { kind: "infected", threat: "EICAR_Test_File", source: "yara", description: "File di test standard EICAR (innocuo)", location: null },
      });
      emit("scan://threat", {
        path: "C:\\Users\\demo\\Desktop\\Fattura_2026.pdf.exe", size: 40960, sha256: null,
        verdict: { kind: "suspicious", score: 100, reasons: ["Doppia estensione ingannevole (.pdf.exe)", "Eseguibile non firmato digitalmente", "Sezione tipica di un packer (UPX0)"] },
      });
      emit("scan://finished", summary);
    }, 200);
  }
}
