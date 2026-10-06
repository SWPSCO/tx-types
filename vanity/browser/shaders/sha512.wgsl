// SHA-512 constants and compression, FIPS 180-4. Words are (low, high).
fn rotate64(a: U64, n: u32) -> U64 {
    if n == 32u { return a.yx; }
    if n < 32u { return (a >> vec2<u32>(n)) | (a.yx << vec2<u32>(32u-n)); }
    return (a.yx >> vec2<u32>(n-32u)) | (a << vec2<u32>(64u-n));
}
fn shift64(a: U64, n: u32) -> U64 {
    return U64((a.x >> n) | (a.y << (32u-n)), a.y >> n);
}
alias ShaState = array<U64, 8>;
alias ShaBlock = array<U64, 16>;

fn sha512_compress(state: ShaState, message: ShaBlock) -> ShaState {
    var schedule = message;
    var a = state[0]; var b = state[1]; var c = state[2]; var d = state[3];
    var e = state[4]; var f = state[5]; var g = state[6]; var h = state[7];
    for (var t = 0u; t < 80u; t++) {
        let slot = t & 15u;
        if t >= 16u {
            let x = schedule[(t-15u) & 15u];
            let y = schedule[(t-2u) & 15u];
            let small0 = rotate64(x, 1u) ^ rotate64(x, 8u) ^ shift64(x, 7u);
            let small1 = rotate64(y, 19u) ^ rotate64(y, 61u) ^ shift64(y, 6u);
            schedule[slot] = add64(add64(schedule[slot], small0), add64(schedule[(t-7u) & 15u], small1));
        }
        let big1 = rotate64(e, 14u) ^ rotate64(e, 18u) ^ rotate64(e, 41u);
        let choose = (e & f) ^ (~e & g);
        let first = add64(add64(add64(h, big1), choose), add64(SHA512_K[t], schedule[slot]));
        let big0 = rotate64(a, 28u) ^ rotate64(a, 34u) ^ rotate64(a, 39u);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let second = add64(big0, majority);
        h = g; g = f; f = e; e = add64(d, first);
        d = c; c = b; b = a; a = add64(first, second);
    }
    return ShaState(add64(state[0], a), add64(state[1], b), add64(state[2], c), add64(state[3], d),
        add64(state[4], e), add64(state[5], f), add64(state[6], g), add64(state[7], h));
}

// Hash exactly 64 bytes after an already-compressed 128-byte HMAC pad.
fn sha512_after_pad(state: ShaState, data: ShaState) -> ShaState {
    var block = ShaBlock();
    for (var i = 0u; i < 8u; i++) { block[i] = data[i]; }
    block[8] = U64(0u, 0x80000000u);
    block[15] = U64(1536u, 0u);
    return sha512_compress(state, block);
}
fn hmac512_64(inner: ShaState, outer: ShaState, data: ShaState) -> ShaState {
    return sha512_after_pad(outer, sha512_after_pad(inner, data));
}
const SHA512_K = array<U64, 80>(U64(3609767458u, 1116352408u),
U64(602891725u, 1899447441u),
U64(3964484399u, 3049323471u),
U64(2173295548u, 3921009573u),
U64(4081628472u, 961987163u),
U64(3053834265u, 1508970993u),
U64(2937671579u, 2453635748u),
U64(3664609560u, 2870763221u),
U64(2734883394u, 3624381080u),
U64(1164996542u, 310598401u),
U64(1323610764u, 607225278u),
U64(3590304994u, 1426881987u),
U64(4068182383u, 1925078388u),
U64(991336113u, 2162078206u),
U64(633803317u, 2614888103u),
U64(3479774868u, 3248222580u),
U64(2666613458u, 3835390401u),
U64(944711139u, 4022224774u),
U64(2341262773u, 264347078u),
U64(2007800933u, 604807628u),
U64(1495990901u, 770255983u),
U64(1856431235u, 1249150122u),
U64(3175218132u, 1555081692u),
U64(2198950837u, 1996064986u),
U64(3999719339u, 2554220882u),
U64(766784016u, 2821834349u),
U64(2566594879u, 2952996808u),
U64(3203337956u, 3210313671u),
U64(1034457026u, 3336571891u),
U64(2466948901u, 3584528711u),
U64(3758326383u, 113926993u),
U64(168717936u, 338241895u),
U64(1188179964u, 666307205u),
U64(1546045734u, 773529912u),
U64(1522805485u, 1294757372u),
U64(2643833823u, 1396182291u),
U64(2343527390u, 1695183700u),
U64(1014477480u, 1986661051u),
U64(1206759142u, 2177026350u),
U64(344077627u, 2456956037u),
U64(1290863460u, 2730485921u),
U64(3158454273u, 2820302411u),
U64(3505952657u, 3259730800u),
U64(106217008u, 3345764771u),
U64(3606008344u, 3516065817u),
U64(1432725776u, 3600352804u),
U64(1467031594u, 4094571909u),
U64(851169720u, 275423344u),
U64(3100823752u, 430227734u),
U64(1363258195u, 506948616u),
U64(3750685593u, 659060556u),
U64(3785050280u, 883997877u),
U64(3318307427u, 958139571u),
U64(3812723403u, 1322822218u),
U64(2003034995u, 1537002063u),
U64(3602036899u, 1747873779u),
U64(1575990012u, 1955562222u),
U64(1125592928u, 2024104815u),
U64(2716904306u, 2227730452u),
U64(442776044u, 2361852424u),
U64(593698344u, 2428436474u),
U64(3733110249u, 2756734187u),
U64(2999351573u, 3204031479u),
U64(3815920427u, 3329325298u),
U64(3928383900u, 3391569614u),
U64(566280711u, 3515267271u),
U64(3454069534u, 3940187606u),
U64(4000239992u, 4118630271u),
U64(1914138554u, 116418474u),
U64(2731055270u, 174292421u),
U64(3203993006u, 289380356u),
U64(320620315u, 460393269u),
U64(587496836u, 685471733u),
U64(1086792851u, 852142971u),
U64(365543100u, 1017036298u),
U64(2618297676u, 1126000580u),
U64(3409855158u, 1288033470u),
U64(4234509866u, 1501505948u),
U64(987167468u, 1607167915u),
U64(1246189591u, 1816402316u));
const SHA512_IV = array<U64, 8>(U64(4089235720u, 1779033703u),
U64(2227873595u, 3144134277u),
U64(4271175723u, 1013904242u),
U64(1595750129u, 2773480762u),
U64(2917565137u, 1359893119u),
U64(725511199u, 2600822924u),
U64(4215389547u, 528734635u),
U64(327033209u, 1541459225u));
