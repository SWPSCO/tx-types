struct MnemonicState {
    inner: ShaState, outer: ShaState, u: ShaState, total: ShaState,
    round: u32, valid: u32,
}
@group(0) @binding(0) var<storage, read> key_blocks: array<ShaBlock>;
@group(0) @binding(1) var<storage, read_write> mnemonic_states: array<MnemonicState>;
@group(0) @binding(2) var<storage, read> config: array<u32>;
@group(0) @binding(3) var<storage, read_write> results: array<Result>;
@group(0) @binding(4) var<storage, read> generator_table: array<Affine>;

@compute @workgroup_size(32)
fn mnemonic_init(@builtin(global_invocation_id) id: vec3<u32>) {
    let lane = id.x;
    if lane >= config[0] { return; }
    var ipad = ShaBlock(); var opad = ShaBlock();
    for (var i = 0u; i < 16u; i++) {
        ipad[i] = key_blocks[lane][i] ^ U64(0x36363636u);
        opad[i] = key_blocks[lane][i] ^ U64(0x5c5c5c5cu);
    }
    let inner = sha512_compress(SHA512_IV, ipad);
    let outer = sha512_compress(SHA512_IV, opad);
    // Salt "mnemonic" followed by the big-endian block counter 1.
    var salt = ShaBlock();
    salt[0] = U64(0x6f6e6963u, 0x6d6e656du);
    salt[1] = U64(0x80000000u, 1u);
    salt[15] = U64(1120u, 0u);
    let u = sha512_after_pad(outer, sha512_compress(inner, salt));
    mnemonic_states[lane] = MnemonicState(inner, outer, u, u, 1u, 0u);
}

// Sixteen bounded dispatches perform the remaining 2047 PBKDF2 rounds.
@compute @workgroup_size(32)
fn mnemonic_pbkdf(@builtin(global_invocation_id) id: vec3<u32>) {
    let lane = id.x;
    if lane >= config[0] { return; }
    var state = mnemonic_states[lane];
    let count = min(128u, 2048u - state.round);
    for (var round = 0u; round < count; round++) {
        state.u = hmac512_64(state.inner, state.outer, state.u);
        for (var i = 0u; i < 8u; i++) { state.total[i] ^= state.u[i]; }
    }
    state.round += count;
    mnemonic_states[lane] = state;
}

fn scalar_valid(words: ShaState) -> bool {
    // Group order generated from Rust, most significant word first.
    var nonzero = 0u;
    for (var i = 0u; i < 4u; i++) { nonzero |= words[i].x | words[i].y; }
    if nonzero == 0u { return false; }
    for (var i = 0u; i < 4u; i++) {
        if less(words[i], CHEETAH_ORDER[i]) { return true; }
        if !equal(words[i], CHEETAH_ORDER[i]) { return false; }
    }
    return false;
}

@compute @workgroup_size(32)
fn mnemonic_master(@builtin(global_invocation_id) id: vec3<u32>) {
    let lane = id.x;
    if lane >= config[0] { return; }
    var key = ShaBlock();
    // HMAC key "Nockchain seed".
    key[0] = U64(0x63686169u, 0x4e6f636bu);
    key[1] = U64(0x65640000u, 0x6e207365u);
    var ipad = ShaBlock(); var opad = ShaBlock();
    for (var i = 0u; i < 16u; i++) {
        ipad[i] = key[i] ^ U64(0x36363636u);
        opad[i] = key[i] ^ U64(0x5c5c5c5cu);
    }
    let inner = sha512_compress(SHA512_IV, ipad);
    let outer = sha512_compress(SHA512_IV, opad);
    var data = mnemonic_states[lane].total;
    var valid = 0u;
    for (var retry = 0u; retry < 256u; retry++) {
        data = hmac512_64(inner, outer, data);
        if scalar_valid(data) { valid = 1u; break; }
    }
    mnemonic_states[lane].u = data;
    mnemonic_states[lane].valid = valid;
}

@compute @workgroup_size(32)
fn mnemonic_address(@builtin(global_invocation_id) id: vec3<u32>) {
    let lane = id.x;
    if lane >= config[0] { return; }
    if mnemonic_states[lane].valid != 1u || mnemonic_states[lane].round != 2048u {
        results[lane] = Result(3u, 0u, 0u, 0u, array<U64, 5>()); return;
    }
    let scalar = mnemonic_states[lane].u;
    var point = Jacobian();
    for (var window = 0u; window < 64u; window++) {
        let word = scalar[3u - window/16u];
        let half = select(word.x, word.y, (window & 15u) >= 8u);
        let digit = (half >> ((window & 7u)*4u)) & 15u;
        if digit != 0u { point = j_mixed_add(point, generator_table[window*16u + digit]); }
    }
    if f6_equal(point.z, F6()) { results[lane] = Result(3u,0u,0u,0u,array<U64,5>()); return; }
    let digest = hash_point(j_affine(point));
    results[lane] = Result(select(0u, 1u, pattern_matches(digest)), 0u, 1u, 0u, digest);
}
