struct Result {
    found: u32, offset: u32, tested: u32, padding: u32,
    digest: array<U64, 5>,
}
struct EncodedPkh { digits: array<u32, 55>, length: u32 }
fn base58_digits(digest: array<U64, 5>) -> EncodedPkh {
    // Convert the base-p digest to 20 little-endian radix-2^16 limbs. Using
    // 16-bit limbs keeps the subsequent division by 58 within u32 range.
    var integer: array<u32, 20>;
    for (var d = 4i; d >= 0i; d--) {
        var words = array<u32, 20>();
        // p = [1, 0, 65535, 65535] in radix 2^16.
        for (var i = 0u; i < 20u; i++) {
            let factors = array<u32, 4>(1u, 0u, 65535u, 65535u);
            var carry = 0u;
            for (var j = 0u; j < 4u && i+j < 20u; j++) {
                let wide = words[i+j] + integer[i] * factors[j] + carry;
                words[i+j] = wide & 65535u;
                carry = wide >> 16u;
            }
            var k = i+4u;
            while carry != 0u && k < 20u {
                let wide = words[k] + carry;
                words[k] = wide & 65535u;
                carry = wide >> 16u;
                k++;
            }
        }
        let digit = digest[u32(d)];
        let addend = array<u32, 4>(digit.x & 65535u, digit.x >> 16u,
            digit.y & 65535u, digit.y >> 16u);
        var carry = 0u;
        for (var i = 0u; i < 20u; i++) {
            var value = 0u;
            if i < 4u { value = addend[i]; }
            let wide = words[i] + value + carry;
            integer[i] = wide & 65535u;
            carry = wide >> 16u;
        }
    }
    var digits: array<u32, 55>;
    var length = 0u;
    loop {
        var remainder = 0u;
        var nonzero = 0u;
        for (var i = 19i; i >= 0i; i--) {
            let wide = (remainder << 16u) | integer[u32(i)];
            integer[u32(i)] = wide / 58u;
            remainder = wide % 58u;
            nonzero |= integer[u32(i)];
        }
        digits[length] = remainder;
        length++;
        if nonzero == 0u || length == 55u { break; }
    }
    return EncodedPkh(digits, length);
}

fn prefix_matches(digest: array<U64, 5>) -> bool {
    let encoded = base58_digits(digest);
    let prefix_length = config[2];
    if encoded.length < prefix_length { return false; }
    for (var i = 0u; i < prefix_length; i++) {
        let digit = encoded.digits[encoded.length - 1u - i];
        let mask = config[4u + i*2u + digit/32u];
        if (mask & (1u << (digit % 32u))) == 0u { return false; }
    }
    return true;
}

