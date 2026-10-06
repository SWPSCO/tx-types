// All views into WASM memory are refreshed after calls that can allocate.
export class WasmKeys {
  constructor(exports) { this.exports = exports; }

  static async load(url = new URL("./generated/vanity_pkh.wasm", import.meta.url)) {
    const response = await fetch(url);
    if (!response.ok) throw new Error("Could not load the address generator.");
    const { instance } = await WebAssembly.instantiate(await response.arrayBuffer(), {});
    return new WasmKeys(instance.exports);
  }

  reset(lanes) {
    if (!Number.isInteger(lanes) || this.exports.reset(lanes) !== 1) {
      throw new Error("Choose between 1 and 256 GPU lanes.");
    }
    this.lanes = lanes;
  }

  prefix(text, insensitive = false) {
    const bytes = new TextEncoder().encode(text);
    if (bytes.length < 1 || bytes.length > 55) throw new Error("Use a prefix of 1 to 55 characters.");
    const e = this.exports;
    new Uint8Array(e.memory.buffer, e.prefix_ptr(), bytes.length).set(bytes);
    if (e.set_prefix(bytes.length, Number(insensitive)) !== 1) {
      throw new Error("This prefix cannot match. Exact mode uses Base58 (no 0, O, I, or l); insensitive mode also accepts their equivalents.");
    }
    return new Uint32Array(e.memory.buffer, e.masks_ptr(), 110).slice();
  }

  setSeed(lane, bytes) {
    if (bytes.length !== 32) throw new Error("A seed must contain 32 bytes.");
    const e = this.exports;
    new Uint8Array(e.memory.buffer, e.seed_ptr(), 32).set(bytes);
    return e.set_seed(lane) === 1;
  }

  seedRandomly() {
    const bytes = new Uint8Array(32);
    try {
      for (let lane = 0; lane < this.lanes; lane++) {
        do { crypto.getRandomValues(bytes); } while (!this.setSeed(lane, bytes));
      }
    } finally { bytes.fill(0); }
  }

  points() {
    const e = this.exports;
    return new Uint32Array(e.memory.buffer, e.points_ptr(), this.lanes * 26).slice();
  }

  reference(lane, offset) {
    const e = this.exports;
    if (e.reference_candidate(lane, offset) !== 1) throw new Error("Invalid reference candidate.");
    return new Uint32Array(e.memory.buffer, e.reference_ptr(), 34).slice();
  }

  verify(lane, offset, keyMode = "raw") {
    const e = this.exports;
    let verified;
    if (keyMode === "extended") {
      const chainCode = new Uint8Array(32);
      try {
        crypto.getRandomValues(chainCode);
        new Uint8Array(e.memory.buffer, e.seed_ptr(), 32).set(chainCode);
        verified = e.verify_extended_match(lane, offset);
      } finally { chainCode.fill(0); }
    } else {
      verified = e.verify_match(lane, offset);
    }
    if (verified !== 1) throw new Error("GPU match failed independent WASM verification.");
    return new Uint8Array(e.memory.buffer, e.output_ptr(), e.output_len()).slice();
  }

  cpuStart() {
    if (this.exports.cpu_start() !== 1) throw new Error("Cannot initialize the WASM CPU search.");
  }

  mnemonicStart(bytes) {
    if (bytes.length !== 32) throw new Error("Mnemonic entropy must contain 32 bytes.");
    const e = this.exports;
    new Uint8Array(e.memory.buffer, e.seed_ptr(), 32).set(bytes);
    if (e.mnemonic_start() !== 1) throw new Error("Cannot initialize mnemonic search.");
  }

  mnemonicGpuStart(bytes) {
    if (bytes.length !== 32) throw new Error("Mnemonic entropy must contain 32 bytes.");
    const e = this.exports;
    new Uint8Array(e.memory.buffer, e.seed_ptr(), 32).set(bytes);
    if (e.mnemonic_gpu_start() !== 1) throw new Error("Cannot initialize GPU mnemonic search.");
  }

  mnemonicGpuPrepare(count) {
    const e = this.exports;
    const prepared = e.mnemonic_gpu_prepare(count);
    if (prepared === 0xffffffff) throw new Error("Invalid GPU mnemonic batch.");
    const input = new Uint32Array(e.memory.buffer, e.mnemonic_gpu_input_ptr(), prepared * 32).slice();
    e.mnemonic_gpu_clear_input();
    return input;
  }

  mnemonicGpuReference(lane) {
    const e = this.exports;
    if (e.mnemonic_gpu_reference(lane) !== 1) throw new Error("Invalid mnemonic reference candidate.");
    return new Uint32Array(e.memory.buffer, e.reference_ptr(), 34).slice();
  }

  mnemonicGpuVerify(lane) {
    const e = this.exports;
    if (e.mnemonic_gpu_verify(lane) !== 1) throw new Error("GPU mnemonic match failed CPU recovery verification.");
    return new Uint8Array(e.memory.buffer, e.output_ptr(), e.output_len()).slice();
  }

  mnemonicBatch() {
    const e = this.exports;
    const status = e.mnemonic_batch();
    if (status === 3) throw new Error("Invalid mnemonic search state.");
    return { status, tested: e.cpu_attempts() };
  }

  mnemonicVerify() {
    const e = this.exports;
    if (e.mnemonic_verify() !== 1) throw new Error("Mnemonic recovery verification failed.");
    return new Uint8Array(e.memory.buffer, e.output_ptr(), e.output_len()).slice();
  }

  mnemonicDigest() {
    const e = this.exports;
    return new Uint32Array(e.memory.buffer, e.reference_ptr() + 24 * 4, 10).slice();
  }

  cpuBatch(limit) {
    const e = this.exports;
    const status = e.cpu_batch(limit);
    if (status === 3) throw new Error("Invalid WASM CPU search state.");
    return { status, tested: e.cpu_attempts(), lane: 0, offset: e.cpu_match_offset() };
  }

  clear() { this.exports.clear(); }
}
