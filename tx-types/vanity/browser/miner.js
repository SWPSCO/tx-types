/**
 * Mine an address without UI dependencies. Both recovery modes automatically
 * select WebGPU when available and otherwise use WASM CPU.
 *
 * @param {import('./miner.js').MineOptions} options
 * @returns {Promise<import('./miner.js').MineResult | null>} null means the attempt limit was reached.
 */
export function mineAddress(options) {
  const { signal, onProgress, workerUrl = new URL("./worker.js", import.meta.url),
    wasmUrl, shaderUrls, mnemonicShaderUrls, tableUrl, ...settings } = options;
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new DOMException("Mining cancelled", "AbortError")); return; }
    let worker;
    try { worker = new Worker(workerUrl, { type: "module" }); }
    catch (error) { reject(error); return; }
    let settled = false;
    let abortTimer;
    const finish = (error, result = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(abortTimer);
      signal?.removeEventListener("abort", abort);
      worker.terminate();
      if (error) reject(error); else resolve(result);
    };
    const aborted = () => finish(new DOMException("Mining cancelled", "AbortError"));
    const abort = () => {
      worker.postMessage({ type: "stop" });
      abortTimer = setTimeout(aborted, 5000);
    };
    signal?.addEventListener("abort", abort, { once: true });
    worker.onerror = (event) => finish(new Error(event.message || "Mining worker failed."));
    worker.onmessageerror = () => finish(new Error("Cannot decode mining worker response."));
    worker.onmessage = ({ data }) => {
      if (signal?.aborted) { if (data.type === "stopped") aborted(); return; }
      if (data.type === "error") finish(new Error(data.message));
      else if (data.type === "stopped") aborted();
      else if (data.type === "limit") finish(null);
      else if (data.type === "match") finish(null, {
        pkh: data.pkh, keyJson: new Uint8Array(data.bytes),
        attempts: data.attempts, backend: data.adapter,
      });
      else {
        try { onProgress?.(data); }
        catch (error) { finish(error); }
      }
    };
    try {
      worker.postMessage({ type: "start", insensitive: false, keyMode: "mnemonic", backend: "auto", lanes: options.keyMode === "raw" ? 64 : 4096,
        steps: 1, maxAttempts: 0, ...settings,
        wasmUrl: wasmUrl === undefined ? undefined : new URL(wasmUrl, import.meta.url).href,
        shaderUrls: shaderUrls?.map(url => new URL(url, import.meta.url).href),
        mnemonicShaderUrls: mnemonicShaderUrls?.map(url => new URL(url, import.meta.url).href),
        tableUrl: tableUrl === undefined ? undefined : new URL(tableUrl, import.meta.url).href,
      });
    } catch (error) { finish(error); }
  });
}
