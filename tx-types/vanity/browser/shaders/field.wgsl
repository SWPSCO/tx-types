// Unsigned 64-bit words are (low, high). All arithmetic uses portable u32.
alias U64 = vec2<u32>;
const P = U64(1u, 0xffffffffu);
const ZERO = U64(0u);
const ONE = U64(1u, 0u);

fn equal(a: U64, b: U64) -> bool { return all(a == b); }
fn less(a: U64, b: U64) -> bool { return a.y < b.y || (a.y == b.y && a.x < b.x); }
fn add64(a: U64, b: U64) -> U64 {
    let lo = a.x + b.x;
    return U64(lo, a.y + b.y + select(0u, 1u, lo < a.x));
}
fn sub64(a: U64, b: U64) -> U64 {
    return U64(a.x - b.x, a.y - b.y - select(0u, 1u, a.x < b.x));
}
// Addition and subtraction take canonical field elements.
fn fadd(a: U64, b: U64) -> U64 {
    var sum = add64(a, b);
    if less(sum, a) { sum = sub64(sum, P); }
    if !less(sum, P) { sum = sub64(sum, P); }
    return sum;
}
fn fsub(a: U64, b: U64) -> U64 {
    if less(a, b) { return sub64(P, sub64(b, a)); }
    return sub64(a, b);
}
fn fneg(a: U64) -> U64 {
    if equal(a, ZERO) { return ZERO; }
    return sub64(P, a);
}

// Full 32x32 -> 64 multiplication using four 16-bit products.
fn mul32(a: u32, b: u32) -> U64 {
    let a0 = a & 65535u;
    let a1 = a >> 16u;
    let b0 = b & 65535u;
    let b1 = b >> 16u;
    let low = a0 * b0;
    let middle = a1 * b0 + (low >> 16u);
    let middle2 = a0 * b1 + (middle & 65535u);
    return U64((middle2 << 16u) | (low & 65535u),
        a1 * b1 + (middle >> 16u) + (middle2 >> 16u));
}
fn mul64(a: U64, b: U64) -> vec4<u32> {
    let ll = mul32(a.x, b.x);
    let lh = mul32(a.x, b.y);
    let hl = mul32(a.y, b.x);
    let hh = mul32(a.y, b.y);
    let mid0 = ll.y + lh.x;
    let mid1 = mid0 + hl.x;
    let c1 = select(0u, 1u, mid0 < ll.y) + select(0u, 1u, mid1 < mid0);
    let high0 = lh.y + hl.y;
    let high1 = high0 + hh.x;
    let high2 = high1 + c1;
    let c2 = select(0u, 1u, high0 < lh.y) + select(0u, 1u, high1 < high0)
        + select(0u, 1u, high2 < high1);
    return vec4<u32>(ll.x, mid1, high2, hh.y + c2);
}
fn fmul(a: U64, b: U64) -> U64 {
    let product = mul64(a, b);
    var low = product.xy;
    let high = U64(product.w, 0u);
    let borrow = less(low, high);
    low = sub64(low, high);
    if borrow { low = add64(low, P); }
    // 2^64 = 2^32 - 1 (mod p), 2^96 = -1 (mod p).
    let folded = sub64(U64(0u, product.z), U64(product.z, 0u));
    return fadd(low, folded);
}
fn finv(a: U64) -> U64 {
    // p-2 = 0xfffffffeffffffff.
    var result = ONE;
    var base = a;
    for (var bit = 0u; bit < 64u; bit++) {
        if bit != 32u { result = fmul(result, base); }
        base = fmul(base, base);
    }
    return result;
}
