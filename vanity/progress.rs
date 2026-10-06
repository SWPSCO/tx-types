//! Shared terminal display for the CPU and GPU command-line runners.
use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant};
use vanity::{format_vanity_duration, Prefix};

pub struct Progress {
    start: Instant,
    reported: Duration,
    estimated: Duration,
    expected_attempts: f64,
    estimate: String,
    terminal: bool,
    drawn: bool,
}

impl Progress {
    pub fn new(prefix: &Prefix) -> Self {
        let mut progress = Self {
            start: Instant::now(),
            reported: Duration::ZERO,
            estimated: Duration::ZERO,
            expected_attempts: prefix.expected_attempts(),
            estimate: "measuring (updates every 30s)".into(),
            terminal: io::stderr().is_terminal() && std::env::var("TERM").as_deref() != Ok("dumb"),
            drawn: false,
        };
        if progress.terminal {
            progress.draw(0, Duration::ZERO);
        }
        progress
    }

    pub fn update(&mut self, attempts: u64) {
        let elapsed = self.start.elapsed();
        let estimate_due = elapsed - self.estimated >= Duration::from_secs(30);
        if estimate_due {
            self.refresh_estimate(attempts, elapsed);
        }
        if elapsed - self.reported >= Duration::from_secs(5) {
            self.draw(attempts, elapsed);
            self.reported = elapsed;
        }
        if estimate_due && !self.terminal {
            eprintln!("Average estimate: {}", self.estimate);
        }
    }

    pub fn finish(&mut self, attempts: u64) {
        let elapsed = self.start.elapsed();
        self.refresh_estimate(attempts, elapsed);
        self.draw(attempts, elapsed);
        // Keep the final display above the result or stop message.
        self.drawn = false;
    }

    fn refresh_estimate(&mut self, attempts: u64, elapsed: Duration) {
        self.estimate = format_vanity_duration(
            self.expected_attempts * elapsed.as_secs_f64() / attempts as f64,
        );
        self.estimated = elapsed;
    }

    fn draw(&mut self, attempts: u64, elapsed: Duration) {
        let rate = attempts as f64 / elapsed.as_secs_f64().max(0.001);
        let elapsed = format_elapsed(elapsed.as_secs());
        let stats = format!("Tested {attempts} candidates · {rate:.0}/s · {elapsed} elapsed");
        if self.terminal {
            let mut stderr = io::stderr().lock();
            let rewind = if self.drawn { "\x1b[2F" } else { "" };
            // Disable wrapping during the redraw so narrow terminals still
            // occupy exactly two rows. Restore wrapping before returning.
            let _ = write!(
                stderr,
                "{rewind}\x1b[?7l\r\x1b[2KAverage estimate: {}\n\r\x1b[2K{stats}\n\x1b[?7h",
                self.estimate
            );
            let _ = stderr.flush();
            self.drawn = true;
        } else {
            eprintln!("{stats}");
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if self.drawn {
            let mut stderr = io::stderr().lock();
            let _ = write!(stderr, "\x1b[2F\r\x1b[J");
            let _ = stderr.flush();
        }
    }
}

fn format_elapsed(seconds: u64) -> String {
    let (minutes, seconds) = (seconds / 60, seconds % 60);
    let (hours, minutes) = (minutes / 60, minutes % 60);
    let (days, hours) = (hours / 24, hours % 24);
    if days > 0 {
        format!("{days}d {hours}h {minutes}m {seconds}s")
    } else if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}
