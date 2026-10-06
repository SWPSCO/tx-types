export function addressFromDigest(words) {
  const prime = 0xffffffff00000001n;
  let integer = 0n;
  for (let i = 4; i >= 0; i--) {
    integer = integer * prime + BigInt(words[i*2]) + (BigInt(words[i*2+1]) << 32n);
  }
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let address = "";
  do { address = alphabet[Number(integer % 58n)] + address; integer /= 58n; } while (integer);
  return address;
}

function assert(condition, message) { if (!condition) throw new Error(`WebGPU self-test: ${message}`); }

// Tests the actual device before generating production keys. This checks both
// scalar-1 doubling and full-width curve arithmetic against the Rust module.
export async function selfTest(gpu, keys) {
  keys.reset(2);
  const one = new Uint8Array(32); one[31] = 1;
  assert(keys.setSeed(0, one) && keys.setSeed(1, new Uint8Array(32).fill(0x35)), "seed setup");
  gpu.initialize(keys.points(), keys.prefix("1"), 1);
  for (let batch = 0; batch < 2; batch++) {
    const results = await gpu.dispatch(2);
    for (const result of results) {
      const expected = keys.reference(result.lane, batch * 2 + 1).slice(24);
      assert(result.status === 0 && result.tested === 2 && result.offset === batch * 2 + 1, "candidate counters");
      assert(result.digest.every((word, i) => word === expected[i]), `PKH parity in lane ${result.lane}, batch ${batch}`);
    }
  }
  // Exercise full Base58 conversion, the exact matcher, and verified output.
  const address = addressFromDigest(keys.reference(0, 1).slice(24));
  gpu.initialize(keys.points(), keys.prefix(address), address.length);
  let results = await gpu.dispatch(2);
  assert(results[0].status === 1 && results[0].offset === 1, "exact prefix match");
  const output = keys.verify(0, 1);
  output.fill(0);
  // The same compiled character masks cover all case and digit equivalences.
  const insensitive = address.toLowerCase().replaceAll("s", "5").replaceAll("a", "4")
    .replaceAll("e", "3").replaceAll("i", "1").replaceAll("l", "1")
    .replaceAll("o", "0").replaceAll("t", "7").replaceAll("b", "8").replaceAll("z", "2");
  gpu.initialize(keys.points(), keys.prefix(insensitive, true), insensitive.length);
  results = await gpu.dispatch(2);
  assert(results[0].status === 1 && results[0].offset === 1, "insensitive prefix match");
  keys.verify(0, 1).fill(0);
  keys.clear();
  gpu.releaseBuffers();
}
