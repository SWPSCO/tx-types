export interface MineOptions {
  prefix: string;
  /** Ignore case and match documented letter/digit alternatives. */
  insensitive?: boolean;
  /** Default: extended (zprv, path m, fresh chain code, no phrase). mnemonic uses 24 words and an empty passphrase. */
  keyMode?: "extended" | "mnemonic" | "raw";
  /** All modes: auto selects WebGPU, then WASM CPU when unavailable or shader compilation fails. */
  backend?: "auto" | "cpu";
  /** GPU lanes: mnemonic 1..4096 (default 4096); extended/raw 1..256 (default 64). */
  lanes?: number;
  /** Extended/raw-key GPU steps per batch (1..16); ignored by mnemonic mining. */
  steps?: number;
  /** Total candidates across all lanes. 0 (default) means unlimited. */
  maxAttempts?: number;
  signal?: AbortSignal;
  onProgress?: (event: MineProgress) => void;
  /** Asset overrides for bundlers or a different static asset layout. */
  workerUrl?: string | URL;
  wasmUrl?: string | URL;
  shaderUrls?: (string | URL)[];
  mnemonicShaderUrls?: (string | URL)[];
  tableUrl?: string | URL;
}

export type MineProgress =
  | { type: "status"; message: string }
  | { type: "backend"; adapter: string; reason: string }
  | { type: "progress"; adapter: string; attempts: number; seconds: number; rate: number };

export interface MineResult {
  pkh: string;
  /** UTF-8 private JSON; extended includes zprv and path m; mnemonic includes phrase and recovery settings. */
  keyJson: Uint8Array;
  attempts: number;
  backend: string;
}

/** Returns null on the attempt limit; rejects with AbortError on cancellation. */
export function mineAddress(options: MineOptions): Promise<MineResult | null>;

/** Expected trials for a uniform PKH, or null for an invalid/impossible prefix. */
export function expectedVanityAttempts(prefix: string, insensitive?: boolean): number | null;
/** Human-readable average duration; null for a non-finite or negative input. */
export function formatVanityDuration(seconds: number): string | null;
