//! Generate the public fixed-base table from the same Rust curve primitives.
use std::io::{BufWriter, Write};
use tx_types::crypto::cheetah_nostd::cheetah_pub_from_sk;
use tx_types::crypto::utils_nostd::add_mod_n;

fn main() -> std::io::Result<()> {
    let path = std::env::args_os().nth(1).expect("output path");
    let mut out = BufWriter::new(std::fs::File::create(path)?);
    let mut power = [0; 32];
    power[31] = 1;
    for _window in 0..64 {
        let mut scalar = [0; 32];
        for digit in 0..16 {
            let (x, y) = if digit == 0 {
                ([0; 6], [0; 6])
            } else {
                cheetah_pub_from_sk(scalar)
            };
            for word in x.into_iter().chain(y) {
                out.write_all(&word.to_le_bytes())?;
            }
            scalar = add_mod_n(&scalar, &power);
        }
        for _ in 0..4 {
            power = add_mod_n(&power, &power);
        }
    }
    out.flush()
}
