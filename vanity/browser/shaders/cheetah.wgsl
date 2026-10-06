alias F6 = array<U64, 6>;
struct Point { x: F6, y: F6, offset: u32, padding: u32 }

fn f6_add(a: F6, b: F6) -> F6 {
    var out: F6;
    for (var i = 0u; i < 6u; i++) { out[i] = fadd(a[i], b[i]); }
    return out;
}
fn f6_sub(a: F6, b: F6) -> F6 {
    var out: F6;
    for (var i = 0u; i < 6u; i++) { out[i] = fsub(a[i], b[i]); }
    return out;
}
fn f6_scale(a: F6, scalar: U64) -> F6 {
    var out: F6;
    for (var i = 0u; i < 6u; i++) { out[i] = fmul(a[i], scalar); }
    return out;
}
fn f6_mul(a: F6, b: F6) -> F6 {
    var wide: array<U64, 11>;
    for (var i = 0u; i < 6u; i++) {
        for (var j = 0u; j < 6u; j++) {
            wide[i+j] = fadd(wide[i+j], fmul(a[i], b[j]));
        }
    }
    for (var i = 6u; i < 11u; i++) {
        wide[i-6u] = fadd(wide[i-6u], fmul(U64(7u, 0u), wide[i]));
    }
    var out: F6;
    for (var i = 0u; i < 6u; i++) { out[i] = wide[i]; }
    return out;
}
fn f6_equal(a: F6, b: F6) -> bool {
    for (var i = 0u; i < 6u; i++) { if !equal(a[i], b[i]) { return false; } }
    return true;
}
fn f6_inv(a: F6) -> F6 {
    var r0: array<U64, 7>;
    r0[0] = fneg(U64(7u, 0u));
    r0[6] = ONE;
    var r1: array<U64, 7>;
    for (var i = 0u; i < 6u; i++) { r1[i] = a[i]; }
    var s0: F6;
    var s1: F6;
    s1[0] = ONE;
    // The remainder degree decreases at every step.
    for (var iteration = 0u; iteration < 7u; iteration++) {
        var degree = 6i;
        while degree >= 0i {
            if !equal(r1[u32(degree)], ZERO) { break; }
            degree--;
        }
        if degree < 0i { return F6(); }
        if degree == 0i { return f6_scale(s1, finv(r1[0])); }
        var quotient = array<U64, 7>();
        let inverse = finv(r1[u32(degree)]);
        for (var i = 6i; i >= degree; i--) {
            let factor = fmul(r0[u32(i)], inverse);
            quotient[u32(i-degree)] = factor;
            for (var j = 0i; j <= degree; j++) {
                let k = u32(i-degree+j);
                r0[k] = fsub(r0[k], fmul(factor, r1[u32(j)]));
            }
        }
        let previous = r0;
        r0 = r1;
        r1 = previous;
        quotient[0] = fadd(quotient[0], fmul(U64(7u, 0u), quotient[6]));
        var q: F6;
        for (var i = 0u; i < 6u; i++) { q[i] = quotient[i]; }
        let next = f6_sub(s0, f6_mul(q, s1));
        s0 = s1;
        s1 = next;
    }
    return F6();
}

// The host reserves the full offset range below the group order. This function
// only encounters finite points; scalar 1 uses the doubling formula.
fn advance(point: Point) -> Point {
    var numerator = f6_sub(GY, point.y);
    var denominator = f6_sub(GX, point.x);
    if f6_equal(point.x, GX) {
        numerator = f6_scale(f6_mul(point.x, point.x), U64(3u, 0u));
        numerator[0] = fadd(numerator[0], ONE);
        denominator = f6_scale(point.y, U64(2u, 0u));
    }
    let slope = f6_mul(numerator, f6_inv(denominator));
    let x = f6_sub(f6_sub(f6_mul(slope, slope), point.x), GX);
    let y = f6_sub(f6_mul(slope, f6_sub(point.x, x)), point.y);
    return Point(x, y, point.offset + 1u, 0u);
}
