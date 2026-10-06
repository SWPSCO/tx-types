// Jacobian coordinates: x=X/Z^2, y=Y/Z^3. Z=0 represents infinity.
// EFD madd-2007-bl and dbl-2007-bl, with Cheetah's a=1:
// https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html
struct Affine { x: F6, y: F6 }
struct Jacobian { x: F6, y: F6, z: F6 }
fn f6_one() -> F6 { var out = F6(); out[0] = ONE; return out; }
fn j_double(p: Jacobian) -> Jacobian {
    if f6_equal(p.z, F6()) || f6_equal(p.y, F6()) { return Jacobian(); }
    let xx = f6_mul(p.x, p.x);
    let yy = f6_mul(p.y, p.y);
    let yyyy = f6_mul(yy, yy);
    let zz = f6_mul(p.z, p.z);
    let sum = f6_add(p.x, yy);
    let s = f6_scale(f6_sub(f6_sub(f6_mul(sum, sum), xx), yyyy), U64(2u, 0u));
    let m = f6_add(f6_scale(xx, U64(3u, 0u)), f6_mul(zz, zz));
    let x = f6_sub(f6_mul(m, m), f6_scale(s, U64(2u, 0u)));
    let y = f6_sub(f6_mul(m, f6_sub(s, x)), f6_scale(yyyy, U64(8u, 0u)));
    let yz = f6_add(p.y, p.z);
    let z = f6_sub(f6_sub(f6_mul(yz, yz), yy), zz);
    return Jacobian(x, y, z);
}
fn j_mixed_add(p: Jacobian, q: Affine) -> Jacobian {
    if f6_equal(p.z, F6()) { return Jacobian(q.x, q.y, f6_one()); }
    let zz = f6_mul(p.z, p.z);
    let u = f6_mul(q.x, zz);
    let s = f6_mul(q.y, f6_mul(p.z, zz));
    let h = f6_sub(u, p.x);
    let r = f6_scale(f6_sub(s, p.y), U64(2u, 0u));
    if f6_equal(h, F6()) {
        if f6_equal(r, F6()) { return j_double(p); }
        return Jacobian();
    }
    let hh = f6_mul(h, h);
    let i = f6_scale(hh, U64(4u, 0u));
    let j = f6_mul(h, i);
    let v = f6_mul(p.x, i);
    let x = f6_sub(f6_sub(f6_mul(r, r), j), f6_scale(v, U64(2u, 0u)));
    let y = f6_sub(f6_mul(r, f6_sub(v, x)), f6_scale(f6_mul(p.y, j), U64(2u, 0u)));
    let zh = f6_add(p.z, h);
    let z = f6_sub(f6_sub(f6_mul(zh, zh), zz), hh);
    return Jacobian(x, y, z);
}
fn j_affine(p: Jacobian) -> Point {
    let inverse = f6_inv(p.z);
    let squared = f6_mul(inverse, inverse);
    return Point(f6_mul(p.x, squared), f6_mul(p.y, f6_mul(squared, inverse)), 0u, 0u);
}
