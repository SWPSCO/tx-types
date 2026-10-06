import test from 'node:test';
import assert from 'node:assert/strict';
import { mineAddress } from '../browser/miner.js';
import { WasmKeys } from '../browser/wasm.js';

for (const [keyMode, expectedMode, lanes] of [[undefined, 'extended', 64], ['extended', 'extended', 64], ['raw', 'raw', 64], ['mnemonic', 'mnemonic', 4096]]) {
  test(`${keyMode ?? 'default'} recovery uses the correct search lane defaults`, async () => {
    const original = globalThis.Worker;
    let message;
    globalThis.Worker = class {
      postMessage(data) {
        message = data;
        queueMicrotask(() => this.onmessage({ data: { type: 'limit' } }));
      }
      terminate() {}
    };
    try {
      const options = { prefix: 'nock' };
      if (keyMode !== undefined) options.keyMode = keyMode;
      assert.equal(await mineAddress(options), null);
      assert.equal(message.keyMode, expectedMode);
      assert.equal(message.lanes, lanes);
    } finally { globalThis.Worker = original; }
  });
}

test('extended export draws a fresh chain code only for the winning key', () => {
  const memory = new WebAssembly.Memory({initial: 1});
  const chainCodes = [];
  let raw = 0;
  const keys = new WasmKeys({
    memory,
    seed_ptr: () => 0,
    output_ptr: () => 64,
    output_len: () => 0,
    verify_match() { raw++; return 1; },
    verify_extended_match(lane, offset) {
      assert.equal(lane, 3);
      assert.equal(offset, 42);
      const input = new Uint8Array(memory.buffer, 0, 32);
      chainCodes.push(input.slice());
      input.fill(0);
      return 1;
    },
  });
  keys.verify(3, 42, 'extended');
  keys.verify(3, 42, 'extended');
  keys.verify(3, 42, 'raw');
  assert.equal(raw, 1);
  assert.equal(chainCodes.length, 2);
  assert.notDeepEqual(chainCodes[0], chainCodes[1]);
  assert.deepEqual(new Uint8Array(memory.buffer, 0, 32), new Uint8Array(32));
});
