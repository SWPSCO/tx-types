use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use tx_types::crypto::utils_nostd::{be32_lt, is_zero32, CHEETAH_N};
use tx_types::crypto::vanity::{
    encode_pkh, key_json, Match, MatchMode, Mnemonic, MnemonicSearch, Prefix, Search,
};
use zeroize::Zeroizing;

const HELP: &str = "Usage: vanity-pkh <PREFIX> --output <FILE> [--insensitive] [--raw-key] [--threads <N>] [--max-attempts <N>]

Mine a Base58 Nockchain public-key hash prefix (exact matching by default).
Search 24-word BIP39 phrases using Nockster's master address (path m, empty passphrase).

  --output FILE      Write the winning key as JSON; file must not exist (0600 on Unix)
  --raw-key          Search raw scalars instead of recoverable mnemonics (faster)
  --threads N        CPU workers (default: available parallelism)
  --max-attempts N   Stop after at most N candidates across all workers
  --insensitive     Ignore case; match a/4, b/8, e/3, i/1, l/1, o/0, s/5, t/7, z/2
                    The letters i and l do not match each other
  -h, --help         Show this help

The output contains the mnemonic, derivation settings, private key, public key, and PKH.
With --raw-key the output has no mnemonic. Keep the file private and backed up.
Only the public PKH and search statistics are printed to the terminal.";

struct Args {
    prefix: Prefix,
    output: PathBuf,
    threads: usize,
    max_attempts: u64,
    raw_key: bool,
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut args = args;
    let mut prefix = None;
    let mut raw_key = false;
    let mut mode = MatchMode::Exact;
    let mut output = None;
    let mut threads = std::thread::available_parallelism().map_or(1, usize::from);
    let mut max_attempts = u64::MAX;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--raw-key" => raw_key = true,
            "--insensitive" => mode = MatchMode::Insensitive,
            "--output" => {
                output = Some(PathBuf::from(args.next().ok_or("missing --output value")?))
            }
            "--threads" => {
                threads = args
                    .next()
                    .ok_or("missing --threads value")?
                    .parse()
                    .map_err(|_| "--threads requires a positive integer")?;
                if threads == 0 {
                    return Err("--threads must be greater than zero".into());
                }
            }
            "--max-attempts" => {
                max_attempts = args
                    .next()
                    .ok_or("missing --max-attempts value")?
                    .parse()
                    .map_err(|_| "--max-attempts requires a positive integer")?;
                if max_attempts == 0 {
                    return Err("--max-attempts must be greater than zero".into());
                }
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option: {arg}")),
            _ if prefix.is_none() => prefix = Some(arg),
            _ => return Err("only one prefix is accepted".into()),
        }
    }
    Ok(Some(Args {
        prefix: Prefix::with_mode(&prefix.ok_or("a Base58 prefix is required")?, mode)
            .map_err(|e| e.to_string())?,
        output: output.ok_or("--output is required")?,
        threads,
        max_attempts,
        raw_key,
    }))
}

fn random_search() -> Result<Search, String> {
    let mut secret = Zeroizing::new([0; 32]);
    loop {
        getrandom::fill(secret.as_mut()).map_err(|e| format!("OS entropy failed: {e}"))?;
        // Rejection sampling is uniform over all nonzero group scalars.
        if !is_zero32(&secret) && be32_lt(&secret, &CHEETAH_N) {
            return Search::new(secret).map_err(|e| e.to_string());
        }
    }
}

fn create_output(path: &PathBuf) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))
}

struct Found {
    key: Match,
    mnemonic: Option<Mnemonic>,
}

fn write_match(file: &mut File, found: &Found) -> Result<(), String> {
    let json = key_json(&found.key, found.mnemonic.as_ref());
    file.write_all(json.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("cannot save winning key: {e}"))
}

enum WorkerSearch {
    Mnemonic(MnemonicSearch),
    Raw(Search),
}

impl WorkerSearch {
    fn random(raw_key: bool) -> Result<Self, String> {
        if raw_key {
            return random_search().map(Self::Raw);
        }
        let mut entropy = Zeroizing::new([0; 32]);
        getrandom::fill(entropy.as_mut()).map_err(|e| format!("OS entropy failed: {e}"))?;
        Ok(Self::Mnemonic(MnemonicSearch::new(entropy)))
    }

    fn batch(&mut self, prefix: &Prefix, limit: u64) -> (u64, Option<Found>, bool) {
        match self {
            Self::Mnemonic(search) => {
                let batch = search.search_batch(prefix, limit);
                (
                    batch.attempts,
                    batch.matched.map(|found| Found {
                        key: found.key,
                        mnemonic: Some(found.mnemonic),
                    }),
                    batch.exhausted,
                )
            }
            Self::Raw(search) => {
                let batch = search.search_batch(prefix, limit);
                (
                    batch.attempts,
                    batch.matched.map(|key| Found {
                        key,
                        mnemonic: None,
                    }),
                    batch.exhausted,
                )
            }
        }
    }
}

fn mine(args: Args) -> Result<bool, String> {
    // Reserve the private file before spending time mining or generating keys.
    let mut output = create_output(&args.output)?;
    let stop = AtomicBool::new(false);
    let claimed = AtomicU64::new(0);
    let completed = AtomicU64::new(0);
    let start = Instant::now();
    eprintln!(
        "Mining {} with {} workers; key output: {}",
        if args.raw_key {
            "raw keys"
        } else {
            "24-word mnemonics (m, empty passphrase)"
        },
        args.threads,
        args.output.display()
    );
    let winner = std::thread::scope(|scope| -> Result<Option<Found>, String> {
        let (sender, receiver) = mpsc::channel();
        let mut workers = Vec::new();
        for _ in 0..args.threads {
            let sender = sender.clone();
            let (stop, claimed, completed) = (&stop, &claimed, &completed);
            let args = &args;
            let worker = std::thread::Builder::new().spawn_scoped(scope, move || {
                let result = (|| -> Result<(), String> {
                    let mut search = WorkerSearch::random(args.raw_key)?;
                    let batch_size = if args.raw_key { 256 } else { 1 };
                    while !stop.load(Ordering::Relaxed) {
                        let claim =
                            claimed.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                                (n < args.max_attempts)
                                    .then(|| n.saturating_add(batch_size).min(args.max_attempts))
                            });
                        let Ok(first) = claim else {
                            break;
                        };
                        let limit = batch_size.min(args.max_attempts - first);
                        let (attempts, matched, exhausted) = search.batch(&args.prefix, limit);
                        completed.fetch_add(attempts, Ordering::Relaxed);
                        if let Some(found) = matched {
                            if !stop.swap(true, Ordering::Relaxed) {
                                sender
                                    .send(found)
                                    .map_err(|_| "result receiver disconnected")?;
                            }
                            break;
                        }
                        if exhausted {
                            search = WorkerSearch::random(args.raw_key)?;
                        }
                    }
                    Ok(())
                })();
                if result.is_err() {
                    stop.store(true, Ordering::Relaxed);
                }
                result
            });
            match worker {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    stop.store(true, Ordering::Relaxed);
                    return Err(format!("cannot start worker: {error}"));
                }
            }
        }
        drop(sender);
        let winner = loop {
            match receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(found) => break Some(found),
                Err(mpsc::RecvTimeoutError::Disconnected) => break None,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let count = completed.load(Ordering::Relaxed);
                    eprintln!(
                        "{count} candidates, {:.0}/s, {:.1}s elapsed",
                        count as f64 / start.elapsed().as_secs_f64(),
                        start.elapsed().as_secs_f64()
                    );
                }
            }
        };
        // Save a winning key before waiting for the remaining workers.
        if let Some(found) = &winner {
            write_match(&mut output, found)?;
        }
        for worker in workers {
            let result = worker.join().map_err(|_| "mining worker panicked")?;
            if winner.is_none() {
                result?;
            }
        }
        Ok(winner)
    })?;
    let count = completed.load(Ordering::Relaxed);
    eprintln!(
        "Tested {count} candidates in {:.2}s ({:.0}/s)",
        start.elapsed().as_secs_f64(),
        count as f64 / start.elapsed().as_secs_f64()
    );
    if let Some(found) = winner {
        println!("{}", encode_pkh(found.key.pkh));
        eprintln!("Key saved to {}", args.output.display());
        Ok(true)
    } else {
        eprintln!(
            "No match within the attempt limit. {} is empty.",
            args.output.display()
        );
        Ok(false)
    }
}

fn main() {
    let result = parse_args(std::env::args().skip(1)).and_then(|args| match args {
        Some(args) => mine(args),
        None => {
            println!("{HELP}");
            Ok(true)
        }
    });
    match result {
        Ok(true) => {}
        Ok(false) => std::process::exit(2),
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tx_types::crypto::cheetah_nostd::{cheetah_pub_from_sk, ser_a_pt};
    use tx_types::crypto::vanity::pkh_from_public_key;

    #[test]
    fn insensitive_flag_works_before_or_after_prefix() {
        for input in [
            vec!["--insensitive", "I", "--output", "key.json"],
            vec!["I", "--output", "key.json", "--insensitive"],
        ] {
            let args = parse_args(input.into_iter().map(String::from))
                .unwrap()
                .unwrap();
            let masks = args.prefix.digit_masks();
            let alphabet = tx_types::crypto::vanity::BASE58_ALPHABET;
            for (letter, expected) in [(b'i', true), (b'1', true), (b'L', false)] {
                let index = alphabet.iter().position(|&b| b == letter).unwrap();
                assert_eq!(masks[0][index / 32] & (1 << (index % 32)) != 0, expected);
            }
        }
        assert!(parse_args(["I", "--output", "key.json"].into_iter().map(String::from)).is_err());
    }

    #[test]
    fn output_contains_a_recoverable_key_and_matching_address() {
        let mut secret_key = Zeroizing::new([0; 32]);
        secret_key[31] = 1;
        let public_key = cheetah_pub_from_sk(*secret_key);
        let pkh = pkh_from_public_key(&public_key);
        let found = Match {
            secret_key_be: secret_key,
            public_key,
            pkh,
        };
        let path = std::env::temp_dir().join(format!(
            "vanity-pkh-output-test-{}.json",
            std::process::id()
        ));
        let mut file = create_output(&path).unwrap();
        write_match(
            &mut file,
            &Found {
                key: Match {
                    secret_key_be: Zeroizing::new(*found.secret_key_be),
                    public_key,
                    pkh,
                },
                mnemonic: None,
            },
        )
        .unwrap();
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let secret_hex = saved["secret_key_hex_be"].as_str().unwrap();
        assert_eq!(secret_hex, format!("{:064x}", 1));
        let decoded = bs58::decode(saved["secret_key_base58"].as_str().unwrap())
            .into_vec()
            .unwrap();
        assert_eq!(decoded, *found.secret_key_be);
        assert_eq!(cheetah_pub_from_sk(decoded.try_into().unwrap()), public_key);
        assert_eq!(saved["pkh"].as_str().unwrap(), encode_pkh(pkh).as_str());
        assert_eq!(
            bs58::decode(saved["public_key_base58"].as_str().unwrap())
                .into_vec()
                .unwrap(),
            ser_a_pt(&public_key)
        );
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
}
