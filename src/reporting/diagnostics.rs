//! Timing and rule-group details serialized into performance reports.

use std::time::Instant;

use serde::Serialize;

#[derive(Default, Serialize)]
pub struct StageTime {
    pub wall_seconds: f64,
    pub cpu_seconds: Option<f64>,
}

pub struct StageClock {
    wall: Instant,
    cpu: Option<f64>,
}

impl StageClock {
    pub fn start() -> Self {
        Self {
            wall: Instant::now(),
            cpu: thread_cpu_seconds(),
        }
    }

    pub fn finish(self) -> StageTime {
        StageTime {
            wall_seconds: self.wall.elapsed().as_secs_f64(),
            cpu_seconds: self
                .cpu
                .zip(thread_cpu_seconds())
                .map(|(start, end)| end - start),
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn thread_cpu_seconds() -> Option<f64> {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // The OS initializes both integer fields on success; no reference to
    // uninitialized memory is formed, and the result is checked before reading.
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, time.as_mut_ptr()) } != 0 {
        return None;
    }
    let time = unsafe { time.assume_init() };
    Some(time.tv_sec as f64 + time.tv_nsec as f64 / 1_000_000_000.0)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn thread_cpu_seconds() -> Option<f64> {
    None
}

#[derive(Serialize)]
pub struct RuleDescription {
    pub rule_id: usize,
    pub line: usize,
    pub service: String,
    pub expression: String,
}

#[derive(Serialize)]
pub struct GroupDescription {
    pub group_id: usize,
    pub engine: &'static str,
    pub minimum_len: Option<usize>,
    pub rules: Vec<RuleDescription>,
}

#[derive(Default, Serialize)]
pub struct GroupTime {
    pub calls: u64,
    pub bytes: u64,
    pub matched_requests: u64,
    pub matched_rules: u64,
    pub search_seconds: f64,
    pub first_64_calls_seconds: f64,
    pub max_call_seconds: f64,
    pub max_request_id: u64,
    pub max_request_bytes: usize,
}

impl GroupTime {
    pub fn record(&mut self, request_id: u64, bytes: usize, seconds: f64, matches: usize) {
        self.calls += 1;
        self.bytes += bytes as u64;
        self.matched_requests += u64::from(matches > 0);
        self.matched_rules += matches as u64;
        self.search_seconds += seconds;
        if self.calls <= 64 {
            self.first_64_calls_seconds += seconds;
        }
        if seconds > self.max_call_seconds {
            self.max_call_seconds = seconds;
            self.max_request_id = request_id;
            self.max_request_bytes = bytes;
        }
    }
}

#[derive(Default, Serialize)]
pub struct MatchingTime {
    pub filter_seconds: f64,
    pub prefix_seconds: f64,
    pub literal_seconds: f64,
    pub literal_occurrences: u64,
    pub distinct_literals_per_request_sum: u64,
    pub result_build_seconds: f64,
    pub groups: Vec<GroupTime>,
}

impl MatchingTime {
    pub fn new(groups: usize) -> Self {
        Self {
            groups: (0..groups).map(|_| GroupTime::default()).collect(),
            ..Self::default()
        }
    }
}
