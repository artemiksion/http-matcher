use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::matcher::Matcher;
use crate::patterns::PatternDatabase;

use super::{run_baseline, run_parallel};

const PATTERNS: &str = "Probe TCP First q||\n\
    softmatch web m|^GET |\n\
    match alpha m|^GET /alpha|\n\
    softmatch submit m|^POST |\n\
    Probe TCP Second q||\n\
    match web m|^GET /alpha|\n\
    match alpha m|alpha|\n";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let path = std::env::temp_dir().join(format!(
            "http-matcher-shards-{}-{}-{}",
            std::process::id(),
            timestamp.as_nanos(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn database(&self, patterns: &str) -> PatternDatabase {
        let path = self.0.join("patterns.txt");
        fs::write(&path, patterns).unwrap();
        PatternDatabase::load(&path).unwrap()
    }

    fn requests(&self, requests: &[Value]) -> PathBuf {
        let path = self.0.join("input.json");
        fs::write(&path, serde_json::to_vec(requests).unwrap()).unwrap();
        path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn results(output: &[u8]) -> Vec<Value> {
    output
        .split(|&byte| byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

#[test]
fn fast_and_baseline_produce_expected_results_on_a_small_sample() {
    let directory = TestDirectory::new();
    let input = directory.requests(&[
        json!({"method":"GET", "url":"/alpha"}),
        json!({"method":"POST", "url":"/alpha"}),
        json!({"method":"GET", "url":"/other"}),
        json!({"method":"DELETE", "url":"/nothing"}),
    ]);
    let database = directory.database(PATTERNS);
    let baseline = Matcher::baseline(&database);
    let shards = Matcher::fast_shards(&database, 2).unwrap();
    let rules = Arc::new(database.rules);
    let mut baseline_output = Vec::new();
    let baseline_stats = run_baseline(
        &input,
        None,
        &baseline,
        Arc::clone(&rules),
        &mut baseline_output,
    )
    .unwrap();
    let mut output = Vec::new();
    let stats = run_parallel(&input, None, shards, rules, &mut output).unwrap();

    assert_eq!(output, baseline_output);
    assert_eq!(stats.requests, 4);
    assert_eq!(stats.bytes, baseline_stats.bytes);
    assert_eq!(stats.matched_requests, 3);
    assert_eq!(
        results(&output),
        vec![
            json!({"request_id":0, "match":["alpha","web"], "softmatch":[]}),
            json!({"request_id":1, "match":["alpha"], "softmatch":["submit"]}),
            json!({"request_id":2, "match":[], "softmatch":["web"]}),
            json!({"request_id":3, "match":[], "softmatch":[]}),
        ]
    );
}
