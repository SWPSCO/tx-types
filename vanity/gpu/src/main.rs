mod gpu;
#[path = "../../progress.rs"]
mod progress;
use progress::Progress;
use vanity::KeyOutput;

use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use vanity::{
    encode_pkh, extended_key_json, key_json, MatchMode, MatchPosition, Pattern, Zeroizing,
};

const HELP: &str =
    "Usage: vanity-gpu [PREFIX | --suffix TEXT | --contains TEXT] --output <FILE> [OPTIONS]
       vanity-gpu --list-gpus
       vanity-gpu --self-test [--adapter N]

Generate a Nockchain address on a native Vulkan GPU. No browser or CUDA toolkit.
Defaults to a zprv extended private key at path m, with no seed phrase.

  --prefix TEXT      Match the start (also accepted as a positional argument)
  --suffix TEXT      Match the end of the address
  --contains TEXT    Match anywhere in the address
  --continuous       Keep finding keys; atomically save a JSON array after each match
  --output FILE      Private JSON backup; must not exist (0600 on Unix)
  --insensitive      Ignore case and match letter/digit equivalents
  --adapter N        Adapter index from --list-gpus (default: discrete GPU)
  --lanes N          Independent random starting keys (default 1024; 1–65536)
  --steps N          Candidates per lane per batch (default 16; 1–16)
  --max-attempts N    Stop after at most N candidates (default: unlimited)
  --raw-key          Export a raw signing key instead of zprv
  --list-gpus        List Vulkan adapters without starting a search
  --self-test        Verify the GPU against Rust without writing a backup
  -h, --help         Show this help

A device self-test runs before every search. Every match is verified in Rust.
Only the public address and statistics are printed. Keep the JSON backup private.
Two terminal lines refresh: progress every 5s, average duration every 30s.
The estimate is an average, not a countdown. Redirected output uses plain lines.
Ctrl+C stops after the current GPU batch. No match leaves the reserved file empty.
Exit codes: 0 match/self-test, 1 error, 2 attempt limit, 130 interrupted.";

struct Args {
    prefix: Option<Pattern>,
    output: Option<PathBuf>,
    adapter: Option<usize>,
    lanes: u32,
    steps: u32,
    max_attempts: u64,
    raw_key: bool,
    continuous: bool,
    list: bool,
    self_test: bool,
}

fn parse(args: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut args = args;
    let mut prefix = None;
    let mut position = MatchPosition::Prefix;
    let mut insensitive = false;
    let mut result = Args {
        prefix: None,
        output: None,
        adapter: None,
        lanes: 1024,
        steps: 16,
        max_attempts: u64::MAX,
        raw_key: false,
        continuous: false,
        list: false,
        self_test: false,
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--list-gpus" => result.list = true,
            "--self-test" => result.self_test = true,
            "--insensitive" => insensitive = true,
            "--raw-key" => result.raw_key = true,
            "--continuous" => result.continuous = true,
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
                result.output = Some(PathBuf::from(args.next().ok_or("Missing --output path")?))
            }
            "--adapter" => {
                result.adapter = Some(
                    args.next()
                        .ok_or("Missing adapter index")?
                        .parse()
                        .map_err(|_| "Invalid adapter index")?,
                )
            }
            "--lanes" => {
                result.lanes = args
                    .next()
                    .ok_or("Missing lane count")?
                    .parse()
                    .map_err(|_| "Invalid lane count")?
            }
            "--steps" => {
                result.steps = args
                    .next()
                    .ok_or("Missing step count")?
                    .parse()
                    .map_err(|_| "Invalid step count")?
            }
            "--max-attempts" => {
                result.max_attempts = args
                    .next()
                    .ok_or("Missing attempt limit")?
                    .parse()
                    .map_err(|_| "Invalid attempt limit")?
            }
            _ if arg.starts_with('-') => return Err(format!("Unknown option: {arg}")),
            _ if prefix.is_none() => prefix = Some(arg),
            _ => return Err("Choose exactly one match pattern".into()),
        }
    }
    if !(1..=65536).contains(&result.lanes) {
        return Err("Use 1–65536 GPU lanes".into());
    }
    if !(1..=16).contains(&result.steps) {
        return Err("Use 1–16 steps per batch".into());
    }
    if result.max_attempts == 0 {
        return Err("The attempt limit must be positive".into());
    }
    if result.list || result.self_test {
        if result.list && result.self_test
            || prefix.is_some()
            || result.output.is_some()
            || result.continuous
        {
            return Err(
                "Use --list-gpus or --self-test on its own, without a prefix or output".into(),
            );
        }
    } else {
        let text = prefix.ok_or("An address prefix is required (see --help)")?;
        result.prefix = Some(
            Pattern::with_mode(
                &text,
                position,
                if insensitive {
                    MatchMode::Insensitive
                } else {
                    MatchMode::Exact
                },
            )
            .map_err(|e| e.to_string())?,
        );
        if result.output.is_none() {
            return Err("--output is required".into());
        }
    }
    Ok(Some(result))
}

fn random_seeds(lanes: u32, stop: &AtomicBool) -> Result<Vec<Zeroizing<[u8; 32]>>, String> {
    let mut seeds = Vec::with_capacity(lanes as usize);
    for _ in 0..lanes {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let mut seed = Zeroizing::new([0; 32]);
        loop {
            getrandom::fill(seed.as_mut()).map_err(|e| format!("OS entropy failed: {e}"))?;
            if gpu::offset_key(&seed, 0).is_some() && gpu::offset_key(&seed, u32::MAX).is_some() {
                break;
            }
        }
        seeds.push(seed);
    }
    Ok(seeds)
}

fn batch_shape(lanes: u32, steps: u32, remaining: u64) -> (u32, u32) {
    let active = u64::from(lanes).min(remaining) as u32;
    (
        active,
        u64::from(steps).min(remaining / u64::from(active)) as u32,
    )
}

fn run(args: Args) -> Result<i32, String> {
    // Reserve the private backup before generating keys or spending GPU time.
    let mut output = args
        .output
        .as_ref()
        .map(|p| {
            KeyOutput::create(p, args.continuous).map_err(|e| format!("Cannot create backup: {e}"))
        })
        .transpose()?;
    let adapters = gpu::adapters();
    if adapters.is_empty() {
        return Err("No Vulkan adapters found. Install the GPU vendor's Vulkan driver.".into());
    }
    if args.list {
        for (i, adapter) in adapters.iter().enumerate() {
            let info = adapter.get_info();
            println!(
                "{i}: {} ({:?}, {}, {})",
                info.name, info.device_type, info.driver, info.driver_info
            );
        }
        return Ok(0);
    }
    let index = args
        .adapter
        .or_else(|| {
            adapters
                .iter()
                .position(|a| a.get_info().device_type == wgpu::DeviceType::DiscreteGpu)
        })
        .or_else(|| {
            adapters
                .iter()
                .position(|a| a.get_info().device_type == wgpu::DeviceType::IntegratedGpu)
        })
        .ok_or("No hardware GPU found. Check --list-gpus and the Vulkan driver.")?;
    let adapter = adapters
        .get(index)
        .ok_or("Adapter index is outside --list-gpus")?;
    let info = adapter.get_info();
    if info.device_type == wgpu::DeviceType::Cpu {
        return Err("The selected Vulkan adapter is software, not a GPU".into());
    }
    let stop = Arc::new(AtomicBool::new(false));
    let interrupted = stop.clone();
    ctrlc::set_handler(move || interrupted.store(true, Ordering::Relaxed))
        .map_err(|e| format!("Cannot install Ctrl+C handler: {e}"))?;
    eprintln!("GPU: {} (Vulkan). Compiling shared shaders…", info.name);
    let gpu = gpu::Gpu::new(adapter)?;
    eprintln!("Checking GPU results against Rust…");
    gpu.self_test()?;
    eprintln!("GPU self-test passed.");
    if stop.load(Ordering::Relaxed) {
        return Ok(130);
    }
    if args.self_test {
        return Ok(0);
    }
    let prefix = args.prefix.as_ref().unwrap();
    let mut seeds = random_seeds(args.lanes, &stop)?;
    if stop.load(Ordering::Relaxed) {
        return Ok(130);
    }
    let mut buffers = gpu.initialize(&seeds, prefix)?;
    let mut offsets = vec![0u32; args.lanes as usize];
    let mut attempts = 0u64;
    eprintln!(
        "Generating {} with {} lanes × {} steps. Ctrl+C stops.",
        if args.raw_key {
            "raw keys"
        } else {
            "zprv keys"
        },
        args.lanes,
        args.steps
    );
    let mut progress = Progress::new(prefix);
    while !stop.load(Ordering::Relaxed) && attempts < args.max_attempts {
        let (active, steps) = batch_shape(args.lanes, args.steps, args.max_attempts - attempts);
        let candidates = gpu.dispatch(&mut buffers, active, steps)?;
        for candidate in &candidates {
            if candidate.status > 2
                || candidate.tested > steps
                || (candidate.tested == 0 && candidate.status != 2)
                || (candidate.status == 0 && candidate.tested != steps)
                || (candidate.status == 2 && candidate.tested == steps)
            {
                return Err("GPU returned invalid candidate counters".into());
            }
            if candidate.tested > 0 {
                let next = offsets[candidate.lane]
                    .checked_add(candidate.tested)
                    .ok_or("GPU offset overflow")?;
                if candidate.offset != next - 1 {
                    return Err("GPU returned a discontinuous candidate offset".into());
                }
                offsets[candidate.lane] = next;
            }
            attempts += u64::from(candidate.tested);
        }
        for candidate in candidates.iter().filter(|c| c.status == 1) {
            let found = gpu::verify(&seeds[candidate.lane], candidate, prefix)?;
            let json = if args.raw_key {
                key_json(&found, None)
            } else {
                let mut chain_code = Zeroizing::new([0; 32]);
                getrandom::fill(chain_code.as_mut())
                    .map_err(|e| format!("OS entropy failed: {e}"))?;
                extended_key_json(&found, &chain_code)
            };
            let file = output.as_mut().unwrap();
            file.save(&json)
                .map_err(|e| format!("Cannot save private backup: {e}"))?;
            progress.finish(attempts);
            println!("{}", encode_pkh(found.pkh));
            eprintln!(
                "Verified match; backup saved to {}",
                args.output.as_ref().unwrap().display()
            );
            if !args.continuous {
                return Ok(0);
            }
        }
        if candidates.iter().any(|c| c.status == 2) {
            seeds = random_seeds(args.lanes, &stop)?;
            if stop.load(Ordering::Relaxed) {
                break;
            }
            buffers = gpu.initialize(&seeds, prefix)?;
            offsets.fill(0);
        }
        progress.update(attempts);
    }
    progress.finish(attempts);
    if stop.load(Ordering::Relaxed) {
        eprintln!("Stopped. Saved matches remain in the output file.");
        Ok(130)
    } else {
        eprintln!("Attempt limit reached. Saved matches remain in the output file.");
        Ok(if output.as_ref().unwrap().count() > 0 {
            0
        } else {
            2
        })
    }
}

fn main() {
    let result = parse(std::env::args().skip(1)).and_then(|args| match args {
        Some(args) => run(args),
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
    #[test]
    fn partial_batches_do_not_exceed_the_attempt_limit() {
        for remaining in 1..40000 {
            let (lanes, steps) = batch_shape(1024, 16, remaining);
            assert!((1..=1024).contains(&lanes));
            assert!((1..=16).contains(&steps));
            assert!(u64::from(lanes) * u64::from(steps) <= remaining);
        }
        assert_eq!(batch_shape(1024, 16, 7), (7, 1));
        assert_eq!(batch_shape(1024, 16, 1025), (1024, 1));
    }
    #[test]
    fn validates_prefixes_and_resource_limits() {
        for args in [
            vec![],
            vec!["x"],
            vec!["0", "--output", "x"],
            vec!["x", "--output", "x", "--lanes", "0"],
            vec!["x", "--output", "x", "--steps", "17"],
            vec!["x", "--output", "x", "--max-attempts", "0"],
            vec!["--self-test", "x"],
        ] {
            assert!(parse(args.into_iter().map(String::from)).is_err());
        }
        let args = parse(
            ["--insensitive", "I", "--output", "x"]
                .into_iter()
                .map(String::from),
        )
        .unwrap()
        .unwrap();
        assert!(!args.raw_key);
        assert_eq!(args.lanes, 1024);
    }
}
