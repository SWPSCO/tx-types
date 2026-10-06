import { addressFromDigest } from "./self-test.js";

function assert(condition, message) { if (!condition) throw new Error(`Mnemonic WebGPU self-test: ${message}`); }

export async function mnemonicSelfTest(gpu, keys) {
  // Both sides of HMAC's 128-byte key boundary, full-width entropy, partial
  // workgroups, and resumed batches run before any production entropy is drawn.
  for (const [value, count] of [[0, 3], [0x42, 2], [255, 1]]) {
    keys.reset(1);
    const masks = keys.prefix("1");
    keys.mnemonicGpuStart(new Uint8Array(32).fill(value));
    gpu.initialize(count, masks, 1);
    const inputs = keys.mnemonicGpuPrepare(count);
    const results = await gpu.dispatch(inputs);
    assert(inputs.every(word => word === 0), "temporary key buffer not erased");
    for (const result of results) {
      const expected = keys.mnemonicGpuReference(result.lane).slice(24);
      assert(result.tested === 1 && result.status < 2, "candidate counter or derivation");
      assert(result.digest.every((word,i) => word === expected[i]), `address parity for entropy ${value}, lane ${result.lane}`);
      assert(result.status === Number(addressFromDigest(expected).startsWith("1")), "prefix match");
    }
    if (value === 0x42) {
      // Continue at the next entropy value, and exercise exact matching/export.
      const inputs = keys.mnemonicGpuPrepare(1);
      const address = addressFromDigest(keys.mnemonicGpuReference(0).slice(24));
      gpu.initialize(1, keys.prefix(address), address.length);
      const [result] = await gpu.dispatch(inputs);
      assert(result.status === 1, "full address match");
      keys.mnemonicGpuVerify(0).fill(0);
    }
  }
  gpu.releaseBuffers(); keys.clear();
}
