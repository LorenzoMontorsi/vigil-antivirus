import { invoke } from "@tauri-apps/api/core";

export type DetectionSource = "hash" | "yara" | "clamav";

export type Verdict =
  | { kind: "clean" }
  | {
      kind: "infected";
      threat: string;
      source: DetectionSource;
      description: string | null;
      location: string | null;
    }
  | { kind: "suspicious"; score: number; reasons: string[] }
  | { kind: "skipped"; reason: string }
  | { kind: "error"; message: string };

export interface ScanResult {
  path: string;
  size: number;
  sha256: string | null;
  verdict: Verdict;
  cached?: boolean;
  signer?: string;
}

export interface ScanSummary {
  scanned: number;
  infected: number;
  suspicious: number;
  skipped: number;
  errors: number;
  cached: number;
  trusted: number;
  cancelled: boolean;
  elapsed_ms: number;
}

export interface SourceStatus {
  name: string;
  ok: boolean;
  message: string;
}

export interface FeedState {
  last_update_unix: number | null;
  yara_forge_release: string | null;
  malwarebazaar_hashes: number;
  sources: SourceStatus[];
}

export interface ClamStatus {
  installed: boolean;
  bundled_version: string | null;
  database: boolean;
  running: boolean;
  starting: boolean;
  version: string | null;
}

export interface Status {
  version: string;
  yara_rules: number;
  hash_signatures: number;
  warnings: string[];
  engine_loading: boolean;
  updating: boolean;
  signatures_dir: string;
  feeds: FeedState;
  clamav_enabled: boolean;
  clamav: ClamStatus;
  cache_entries: number;
  quarantine_count: number;
}

export interface QuarantineItem {
  id: string;
  original_path: string;
  threat: string;
  source: string;
  sha256: string;
  size: number;
  quarantined_at: number;
}

export interface QuarantineRequest {
  path: string;
  threat: string;
  source: string;
}

export interface QuarantineOutcome {
  path: string;
  ok: boolean;
  error: string | null;
}

export interface Exclusions {
  paths: string[];
  extensions: string[];
}

export type RulesPackage = "core" | "extended" | "none";

export interface Settings {
  exclusions: Exclusions;
  max_file_size_mb: number;
  heuristics: boolean;
  scan_archives: boolean;
  trust_microsoft: boolean;
  use_cache: boolean;
  auto_quarantine: boolean;
  rules_package: RulesPackage;
  malwarebazaar_key: string;
  auto_update: boolean;
  clamav_enabled: boolean;
  start_at_login: boolean;
}

export type ScanKind = "quick" | "full" | "custom";

export const api = {
  status: () => invoke<Status>("status"),
  reloadSignatures: () => invoke<void>("reload_signatures"),
  updateSignatures: () => invoke<void>("update_signatures"),
  startClamav: () => invoke<void>("start_clamav"),
  openSignaturesDir: () => invoke<void>("open_signatures_dir"),
  getSettings: () => invoke<Settings>("get_settings"),
  saveSettings: (settings: Settings) => invoke<void>("save_settings", { settings }),
  startScan: (kind: ScanKind, paths?: string[], ignoreCache = false) =>
    invoke<void>("start_scan", { kind, paths: paths ?? null, ignoreCache }),
  clearCache: () => invoke<void>("clear_cache"),
  quarantineAdd: (items: QuarantineRequest[]) => invoke<QuarantineOutcome[]>("quarantine_add", { items }),
  quarantineList: () => invoke<QuarantineItem[]>("quarantine_list"),
  quarantineRestore: (id: string, exclude: boolean) => invoke<string>("quarantine_restore", { id, exclude }),
  quarantineDelete: (ids: string[]) => invoke<void>("quarantine_delete", { ids }),
  cancelScan: () => invoke<void>("cancel_scan"),
};

export function errorText(e: unknown): string {
  return typeof e === "string" ? e : e instanceof Error ? e.message : JSON.stringify(e);
}

export function formatDuration(ms: number): string {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const pad = (n: number) => n.toString().padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${pad(m)}:${pad(sec)}`;
}

export function formatAgo(unix: number | null): string {
  if (!unix) return "mai";
  const diff = Math.max(0, Date.now() / 1000 - unix);
  if (diff < 60) return "pochi secondi fa";
  if (diff < 3600) return `${Math.floor(diff / 60)} min fa`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} h fa`;
  return new Date(unix * 1000).toLocaleDateString("it-IT");
}

export const SOURCE_LABEL: Record<DetectionSource, string> = {
  hash: "Hash",
  yara: "YARA",
  clamav: "ClamAV",
};

export const nf = new Intl.NumberFormat("it-IT");

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toLocaleString("it-IT", { maximumFractionDigits: 1 })} ${units[i]}`;
}

/** Richiesta di quarantena per un risultato di scansione. */
export function quarantineRequest(r: ScanResult): QuarantineRequest | null {
  const v = r.verdict;
  if (v.kind === "infected") return { path: r.path, threat: v.threat, source: v.source };
  if (v.kind === "suspicious") return { path: r.path, threat: "Sospetto (euristica)", source: "heuristics" };
  return null;
}

// ── Protezione in tempo reale (servizio VigilRtd) ─────────────────────────

export interface RtStats {
  exec_checked: number;
  exec_blocked: number;
  exec_cached: number;
  writes_checked: number;
  threats_found: number;
  quarantined: number;
}

export interface RtStatus {
  version: string;
  driver_connected: boolean;
  started_at: number;
  auto_quarantine: boolean;
  yara_rules: number;
  hash_signatures: number;
  stats: RtStats;
  last_event_id: number;
  /** 0 = attiva; altrimenti istante unix di ripresa (o il massimo u64 = fino al riavvio). */
  paused_until: number;
  exclusions: number;
}

export type RtEventKind = "blocked" | "quarantined" | "detected" | "quarantine_failed";

export interface RtEvent {
  id: number;
  time: number;
  kind: RtEventKind;
  path: string;
  threat: string;
  process: string | null;
  detail: string | null;
}

export interface RtUiStatus {
  installed: boolean;
  running: boolean;
  status: RtStatus | null;
}

/** Stato sintetico per l'interfaccia. */
export type RtState = "not_installed" | "stopped" | "starting" | "active" | "paused";

export function rtState(s: RtUiStatus | null): RtState {
  if (!s || !s.installed) return "not_installed";
  if (!s.running) return "stopped";
  if (s.status && s.status.paused_until > 0) return "paused";
  return s.status?.driver_connected ? "active" : "starting";
}

export const rtApi = {
  status: () => invoke<RtUiStatus>("rt_status"),
  events: () => invoke<RtEvent[]>("rt_events"),
  setEnabled: (enabled: boolean) => invoke<void>("rt_set_enabled", { enabled }),
  pause: (minutes: number | null) => invoke<void>("rt_pause", { minutes }),
  vaultList: () => invoke<QuarantineItem[]>("rt_vault_list"),
  vaultRestore: (id: string, exclude: boolean) => invoke<void>("rt_vault_restore", { id, exclude }),
  vaultDelete: (ids: string[]) => invoke<void>("rt_vault_delete", { ids }),
  resume: () => invoke<void>("rt_resume"),
};
