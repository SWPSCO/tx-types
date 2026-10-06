#[path = "../../progress.rs"]
mod progress;
use progress::Progress;
use vanity::KeyOutput;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use tx_types::crypto::utils_nostd::{be32_lt, is_zero32, CHEETAH_N};
use vanity::{
    encode_pkh, key_json, Match, MatchMode, MatchPosition, Mnemonic, MnemonicSearch, Pattern,
    Search,
};
use zeroize::Zeroizing;

const HELP: &str = "Usage: vanity-pkh [PREFIX | --suffix TEXT | --contains TEXT] --output <FILE> [--insensitive] [--raw-key] [--threads <N>] [--max-attempts <N>]

Mine a Base58 Nockchain public-key hash prefix (exact matching by default).
Search 24-word BIP39 phrases using Nockster's master address (path m, empty passphrase).

  --prefix TEXT      Match the start (also accepted as a positional argument)
  --suffix TEXT      Match the end of the address
  --contains TEXT    Match anywhere in the address
  --continuous       Keep finding keys; atomically save a JSON array after each match
  --output FILE      Write the winning key as JSON; file must not exist (0600 on Unix)
  --raw-key          Search raw scalars instead of recoverable mnemonics (faster)
  --threads N        CPU workers (default: available parallelism)
  --max-attempts N   Stop after at most N candidates across all workers
  --insensitive     Ignore case; match a/4, b/8, e/3, i/1, l/1, o/0, s/5, t/7, z/2
                    The letters i and l do not match each other
  -h, --help         Show this help

The output contains the mnemonic, derivation settings, private key, public key, and PKH.
With --raw-key the output has no mnemonic. Keep the file private and backed up.
Only the public PKH and search statistics are printed to the terminal.
Two terminal lines refresh: progress every 5s, average duration every 30s.
The estimate is an average, not a countdown. Redirected output uses plain lines.";

struct Args {
    prefix: Pattern,
    output: PathBuf,
    threads: usize,
    max_attempts: u64,
    raw_key: bool,
    continuous: bool,
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut args = args;
    let mut prefix = None;
    let mut position = MatchPosition::Prefix;
    let mut raw_key = false;
    let mut continuous = false;
    let mut mode = MatchMode::Exact;
    let mut output = None;
    let mut threads = std::thread::available_parallelism().map_or(1, usize::from);
    let mut max_attempts = u64::MAX;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--raw-key" => raw_key = true,
            "--continuous" => continuous = true,
            "--insensitive" => mode = MatchMode::Insensitive,
            "--prefix" | "--suffix" | "--contains" => {
                if prefix.is_some() {
                    return Err("Choose exactly one of prefix, --suffix, or --contains".into());
                }
                position = match arg.as_str() {
                    "--suffix" => MatchPosition::Suffix,
                    "--contains" => MatchPosition::Contains,
                    _ => MatchPosition::Prefix,
                };
                prefix = Some(args.next().ok_or("missing pattern value")?);
            }
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
            _ => return Err("choose exactly one match pattern".into()),
        }
    }
    Ok(Some(Args {
        prefix: Pattern::with_mode(
            &prefix.ok_or("a Base58 match pattern is required")?,
            position,
            mode,
        )
        .map_err(|e| e.to_string())?,
        output: output.ok_or("--output is required")?,
        threads,
        max_attempts,
        raw_key,
        continuous,
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

struct Found {
    key: Match,
    mnemonic: Option<Mnemonic>,
}

fn write_match(file: &mut KeyOutput, found: &Found) -> Result<(), String> {
    let json = key_json(&found.key, found.mnemonic.as_ref());
    file.save(&json)
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

    fn batch(&mut self, prefix: &Pattern, limit: u64) -> (u64, Option<Found>, bool) {
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

fn mine(args: Args) -> Result<i32, String> {
    let mut output = KeyOutput::create(&args.output, args.continuous)
        .map_err(|e| format!("cannot create backup: {e}"))?;
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let interrupted = std::sync::Arc::new(AtomicBool::new(false));
    let (signal_stop, signal_interrupted) = (stop.clone(), interrupted.clone());
    ctrlc::set_handler(move || {
        signal_interrupted.store(true, Ordering::Relaxed);
        signal_stop.store(true, Ordering::Relaxed);
    })
    .map_err(|e| format!("cannot install Ctrl+C handler: {e}"))?;
    let claimed = AtomicU64::new(0);
    let completed = AtomicU64::new(0);
    eprintln!(
        "Mining with {} workers; key output: {}",
        args.threads,
        args.output.display()
    );
    let mut progress = Progress::new(&args.prefix);
    std::thread::scope(|scope| -> Result<(), String> {
        // Bound queued private material and apply backpressure while saving.
        let (sender, receiver) = mpsc::sync_channel(args.threads);
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
                        // Consume the whole reservation, including after a match.
                        let mut remaining = limit;
                        while remaining > 0 && !stop.load(Ordering::Relaxed) {
                            let (attempts, matched, exhausted) =
                                search.batch(&args.prefix, remaining);
                            completed.fetch_add(attempts, Ordering::Relaxed);
                            remaining -= attempts;
                            if let Some(found) = matched {
                                if args.continuous || !stop.swap(true, Ordering::Relaxed) {
                                    sender
                                        .send(found)
                                        .map_err(|_| "result receiver disconnected")?;
                                }
                            }
                            if exhausted {
                                search = WorkerSearch::random(args.raw_key)?;
                            }
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
                    drop(receiver);
                    return Err(format!("cannot start worker: {error}"));
                }
            }
        }
        drop(sender);
        let mut save_error = None;
        loop {
            match receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(found) => {
                    if let Err(error) = write_match(&mut output, &found) {
                        stop.store(true, Ordering::Relaxed);
                        save_error = Some(error);
                        break;
                    }
                    progress.finish(completed.load(Ordering::Relaxed));
                    println!("{}", encode_pkh(found.key.pkh));
                    eprintln!(
                        "Match {} saved to {}",
                        output.count(),
                        args.output.display()
                    );
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    progress.update(completed.load(Ordering::Relaxed))
                }
            }
        }
        // Disconnect before joining so a failed save cannot strand a sender.
        drop(receiver);
        let mut worker_error = None;
        for worker in workers {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    worker_error.get_or_insert(error);
                }
                Err(_) => {
                    worker_error.get_or_insert("mining worker panicked".into());
                }
            }
        }
        if let Some(error) = save_error.or(worker_error) {
            return Err(error);
        }
        Ok(())
    })?;
    progress.finish(completed.load(Ordering::Relaxed));
    eprintln!(
        "{} matches saved to {}",
        output.count(),
        args.output.display()
    );
    Ok(if interrupted.load(Ordering::Relaxed) {
        130
    } else if output.count() > 0 {
        0
    } else {
        2
    })
}

fn main() {
    let result = parse_args(std::env::args().skip(1)).and_then(|args| match args {
        Some(args) => mine(args),
        None => {
            println!("{HELP}");
            Ok(0)
        }
    });
    match result {
        Ok(code) => std::process::exit(code),
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
    use vanity::pkh_from_public_key;

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
            let alphabet = vanity::BASE58_ALPHABET;
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
        let mut file = KeyOutput::create(&path, false).unwrap();
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
