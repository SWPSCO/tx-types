fn lookup_word(word: u32) -> u32 {
    return LOOKUP[word & 255u] | (LOOKUP[(word >> 8u) & 255u] << 8u)
        | (LOOKUP[(word >> 16u) & 255u] << 16u) | (LOOKUP[word >> 24u] << 24u);
}
fn permute(input: array<U64, 16>) -> array<U64, 16> {
    var state = input;
    for (var round = 0u; round < 7u; round++) {
        var substituted: array<U64, 16>;
        for (var i = 0u; i < 4u; i++) {
            substituted[i] = U64(lookup_word(state[i].x), lookup_word(state[i].y));
        }
        for (var i = 4u; i < 16u; i++) {
            let square = fmul(state[i], state[i]);
            let fourth = fmul(square, square);
            substituted[i] = fmul(fmul(fourth, square), state[i]);
        }
        for (var i = 0u; i < 16u; i++) {
            var sum = ZERO;
            for (var j = 0u; j < 16u; j++) {
                sum = fadd(sum, fmul(U64(MDS[(j + 16u - i) % 16u], 0u), substituted[j]));
            }
            state[i] = fadd(sum, ROUND_CONSTANTS[round * 16u + i]);
        }
    }
    return state;
}
fn hash_point(point: Point) -> array<U64, 5> {
    var transcript: array<U64, 40>;
    transcript[0] = U64(13u, 0u);
    for (var i = 0u; i < 6u; i++) {
        transcript[i+1u] = point.x[i];
        transcript[i+7u] = point.y[i];
    }
    transcript[13] = ONE;
    for (var i = 0u; i < 24u; i++) { transcript[14u+i] = U64(DYCK[i], 0u); }
    transcript[38] = ONE; // TIP5 varlen padding
    var state: array<U64, 16>;
    for (var block = 0u; block < 4u; block++) {
        for (var i = 0u; i < 10u; i++) {
            state[i] = fmul(transcript[block * 10u + i], MONT_R);
        }
        state = permute(state);
    }
    var digest: array<U64, 5>;
    for (var i = 0u; i < 5u; i++) { digest[i] = fmul(state[i], MONT_R_INVERSE); }
    return digest;
}
