import { WasmKeys } from "./wasm.js";
import { GpuSearch, WebGpuUnavailableError } from "./gpu.js";
import { MnemonicGpuSearch } from "./mnemonic-gpu.js";
import { mnemonicSelfTest } from "./mnemonic-self-test.js";
import { addressFromDigest, selfTest } from "./self-test.js";

let active = false;
let cancelled = false;
let gpu;
const status = (message) => postMessage({ type: "status", message });

async function mineMnemonic(keys, options) {
  const { prefix, insensitive, maxAttempts, lanes, backend = "auto" } = options;
  let reason = "CPU selected";
  if (backend === "auto") {
    status("Preparing GPU mnemonic derivation…");
    try { gpu = await MnemonicGpuSearch.create(options); }
    catch (error) {
      if (!(error instanceof WebGpuUnavailableError)) throw error;
      reason = error.message;
    }
  }
  if (cancelled) return;
  if (gpu) {
    status("Checking GPU mnemonic recovery against Rust…");
    await mnemonicSelfTest(gpu, keys);
  }
  if (cancelled) return;
  keys.reset(1);
  const masks = keys.prefix(prefix, insensitive);
  const entropy = new Uint8Array(32);
  try {
    crypto.getRandomValues(entropy);
    if (gpu) keys.mnemonicGpuStart(entropy); else keys.mnemonicStart(entropy);
  } finally { entropy.fill(0); }
  if (gpu) gpu.initialize(lanes, masks, prefix.length);
  const adapter = gpu ? `WebGPU · ${gpu.adapterName}` : "CPU · WASM";
  postMessage({ type: "backend", adapter, reason: gpu ? "24-word mnemonic search." : reason });
  const started = performance.now();
  let attempts = 0;
  while (!cancelled && (!maxAttempts || attempts < maxAttempts)) {
    let results;
    if (gpu) {
      const count = Math.min(lanes, maxAttempts ? maxAttempts - attempts : lanes);
      const input = keys.mnemonicGpuPrepare(count);
      if (!input.length) throw new Error("Mnemonic entropy range exhausted. Start a fresh search.");
      results = await gpu.dispatch(input);
    } else {
      results = [keys.mnemonicBatch()];
      await new Promise(resolve => setTimeout(resolve, 0));
    }
    if (cancelled) return;
    if (results.some(result => result.status === 3)) throw new Error("GPU mnemonic derivation failed.");
    attempts += results.reduce((sum, result) => sum + result.tested, 0);
    const found = results.find(result => result.status === 1);
    if (found) {
      const bytes = gpu ? keys.mnemonicGpuVerify(found.lane) : keys.mnemonicVerify();
      const digest = keys.mnemonicDigest();
      if (gpu && !found.digest.every((word,i) => word === digest[i])) {
        bytes.fill(0); throw new Error("GPU mnemonic address failed CPU verification.");
      }
      const pkh = addressFromDigest(digest);
      postMessage({ type: "match", pkh, bytes: bytes.buffer, attempts, adapter }, [bytes.buffer]);
      return;
    }
    if (results.some(result => result.status === 2)) throw new Error("Mnemonic entropy range exhausted. Start a fresh search.");
    const seconds = (performance.now() - started) / 1000;
    postMessage({ type: "progress", attempts, seconds, rate: attempts / seconds, adapter });
  }
  if (!cancelled) postMessage({ type: "limit", attempts });
}

self.onmessage = async ({ data }) => {
  if (data.type === "stop") {
    cancelled = true;
    gpu?.destroy();
    return;
  }
  if (data.type !== "start" || active) return;
  active = true;
  cancelled = false;
  let keys;
  try {
    const { prefix, insensitive, lanes, steps, maxAttempts, backend = "auto", keyMode = "extended" } = data;
    if (!["auto", "cpu"].includes(backend)) throw new Error("Choose Automatic or CPU for the backend.");
    if (!["extended", "mnemonic", "raw"].includes(keyMode)) throw new Error("Choose an extended key, mnemonic, or raw key.");
    if (!Number.isInteger(steps) || steps < 1 || steps > 16) throw new Error("Steps must be between 1 and 16.");
    if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 0) throw new Error("Attempt limit must be a nonnegative safe integer.");
    keys = await WasmKeys.load(data.wasmUrl);
    if (cancelled) return;
    keys.reset(keyMode === "mnemonic" ? 1 : lanes);
    keys.prefix(prefix, insensitive);
    if (keyMode === "mnemonic") {
      await mineMnemonic(keys, data);
      return;
    }
    let cpuReason = "CPU selected";
    if (backend === "auto") {
      status("Checking WebGPU availability…");
      try { gpu = await GpuSearch.create({ shaderUrls: data.shaderUrls }); }
      catch (error) {
        if (!(error instanceof WebGpuUnavailableError)) throw error;
        cpuReason = error.message;
      }
    }
    if (cancelled) return;
    if (gpu) {
      status("Checking GPU results against WASM…");
      await selfTest(gpu, keys);
    }
    if (cancelled) return;
    keys.reset(gpu ? lanes : 1);
    const masks = keys.prefix(prefix, insensitive);
    status("Generating private starting keys…");
    keys.seedRandomly();
    if (gpu) gpu.initialize(keys.points(), masks, prefix.length);
    else keys.cpuStart();
    const adapter = gpu ? `WebGPU · ${gpu.adapterName}` : "CPU · WASM";
    postMessage({ type: "backend", adapter, reason: gpu ? "" : cpuReason });
    const started = performance.now();
    let attempts = 0;
    while (!cancelled) {
      // A partial last batch runs only the remaining number of lanes. The
      // active-lane count lives in config; persistent point storage is intact.
      const remaining = maxAttempts ? maxAttempts - attempts : Number.MAX_SAFE_INTEGER;
      if (remaining <= 0) break;
      let activeResults;
      if (gpu) {
        const batchSteps = Math.min(steps, Math.max(1, Math.floor(remaining / lanes)));
        gpu.config[0] = Math.min(lanes, remaining);
        const results = await gpu.dispatch(batchSteps);
        // Inactive lanes retain their previous result records; exclude them.
        activeResults = results.slice(0, gpu.config[0]);
      } else {
        activeResults = [keys.cpuBatch(Math.min(128, remaining))];
        // Yield a task, not just a microtask, so Stop messages can be handled.
        await new Promise(resolve => setTimeout(resolve, 0));
      }
      attempts += activeResults.reduce((sum, result) => sum + result.tested, 0);
      const found = activeResults.find((result) => result.status === 1);
      if (cancelled) break;
      if (found) {
        const bytes = keys.verify(found.lane, found.offset, keyMode);
        const pkh = addressFromDigest(keys.reference(found.lane, found.offset).slice(24));
        postMessage({ type: "match", pkh, bytes: bytes.buffer, attempts, adapter }, [bytes.buffer]);
        return;
      }
      if (activeResults.some((result) => result.status === 2)) throw new Error("Search offset range exhausted. Start a fresh search.");
      const seconds = (performance.now() - started) / 1000;
      postMessage({ type: "progress", attempts, seconds, rate: attempts / seconds, adapter });
    }
    if (!cancelled) postMessage({ type: "limit", attempts });
  } catch (error) {
    if (!cancelled) postMessage({ type: "error", message: error.message });
  } finally {
    keys?.clear();
    gpu?.destroy();
    gpu = undefined;
    active = false;
    if (cancelled) postMessage({ type: "stopped" });
  }
};
