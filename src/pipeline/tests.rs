use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crossbeam_channel::bounded;
use serde_json::{json, Value};

use crate::matcher::{Matcher, ResultBuilder};
use crate::normalize::Request;
use crate::patterns::PatternDatabase;

use super::{
    run_baseline, run_parallel, write_batches, PartialBatch, RequestBatch, BATCH_BYTE_LIMIT,
    BATCH_REQUEST_LIMIT,
};

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

fn completes_without_deadlock<T: Send + 'static>(
    operation: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (sender, receiver) = mpsc::sync_channel(1);
    let handle = thread::spawn(move || {
        let _ = sender.send(operation());
    });
    let result = receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("pipeline did not terminate within 10 seconds");
    handle.join().unwrap();
    result
}

#[test]
fn every_request_reaches_every_shard_and_results_match_baseline() {
    let directory = TestDirectory::new();
    let input = directory.0.join("requests");
    fs::create_dir(&input).unwrap();
    // Files created in reverse order must still be read in sorted path order.
    for (name, method) in [("z-post.json", "POST"), ("a-get.json", "GET")] {
        let requests: Vec<_> = (0..400)
            .map(|index| json!({"method": method, "url": format!("/alpha/{index}")}))
            .collect();
        fs::write(input.join(name), serde_json::to_vec(&requests).unwrap()).unwrap();
    }
    let database = directory.database(PATTERNS);
    let baseline = Matcher::baseline(&database);
    let rules = Arc::new(database.rules.clone());
    for limit in [None, Some(513), Some(0)] {
        let mut expected = Vec::new();
        let baseline_stats =
            run_baseline(&input, limit, &baseline, Arc::clone(&rules), &mut expected).unwrap();
        for workers in [1, 2, 3, 8] {
            let shards = Matcher::fast_shards(&database, workers).unwrap();
            let mut output = Vec::new();
            let stats =
                run_parallel(&input, limit, shards, Arc::clone(&rules), &mut output).unwrap();
            assert_eq!(output, expected, "workers={workers}, limit={limit:?}");
            assert_eq!(stats.requests, baseline_stats.requests);
            assert_eq!(stats.bytes, baseline_stats.bytes);
            assert_eq!(stats.matched_requests, baseline_stats.matched_requests);
        }
        if limit.is_none() {
            let rows = results(&expected);
            assert_eq!(rows.len(), 800);
            for (id, row) in rows.iter().enumerate() {
                assert_eq!(row["request_id"], id);
            }
            // Soft and hard web matches live in different shards with two workers.
            assert_eq!(rows[0]["match"], json!(["alpha", "web"]));
            assert_eq!(rows[0]["softmatch"], json!([]));
            assert_eq!(rows[400]["match"], json!(["alpha"]));
            assert_eq!(rows[400]["softmatch"], json!(["submit"]));
        }
    }
}

#[test]
fn byte_limited_batches_and_oversized_request_preserve_results_and_byte_counts() {
    let directory = TestDirectory::new();
    let database = directory.database(PATTERNS);
    let input = directory.requests(&[
        json!({"method":"GET", "url":"/alpha", "body":"x".repeat(BATCH_BYTE_LIMIT / 2)}),
        json!({"method":"POST", "url":"/", "body":"x".repeat(BATCH_BYTE_LIMIT / 2)}),
        json!({"method":"GET", "url":"/alpha", "body":"x".repeat(BATCH_BYTE_LIMIT + 1)}),
        json!({"method":"DELETE", "url":"/nothing", "body":"\u{0000}"}),
    ]);
    let baseline = Matcher::baseline(&database);
    let shards = Matcher::fast_shards(&database, 3).unwrap();
    let rules = Arc::new(database.rules);
    let mut expected = Vec::new();
    let baseline_stats =
        run_baseline(&input, None, &baseline, Arc::clone(&rules), &mut expected).unwrap();
    let mut output = Vec::new();
    let stats = run_parallel(&input, None, shards, rules, &mut output).unwrap();
    assert_eq!(output, expected);
    assert_eq!(stats.requests, 4);
    assert_eq!(stats.bytes, baseline_stats.bytes);
    assert_eq!(stats.matched_requests, 3);
    assert_eq!(results(&output)[3]["match"], json!([]));
    assert_eq!(results(&output)[3]["softmatch"], json!([]));
}

#[test]
fn empty_corpus_and_empty_rule_shards_complete() {
    let directory = TestDirectory::new();
    for patterns in [PATTERNS, "Probe TCP Empty q||\n"] {
        let database = directory.database(patterns);
        for requests in [Vec::new(), vec![json!({"method":"DELETE", "url":"/"})]] {
            let input = directory.requests(&requests);
            let shards = Matcher::fast_shards(&database, 8).unwrap();
            let mut output = Vec::new();
            let stats = run_parallel(
                &input,
                None,
                shards,
                Arc::new(database.rules.clone()),
                &mut output,
            )
            .unwrap();
            assert_eq!(stats.requests, requests.len());
            assert_eq!(stats.matched_requests, 0);
            assert_eq!(results(&output).len(), requests.len());
        }
    }
}

#[test]
fn no_workers_is_rejected_before_reading() {
    let mut output = Vec::new();
    let error = run_parallel(
        std::path::Path::new("unused-input"),
        None,
        Vec::new(),
        Arc::new(Vec::new()),
        &mut output,
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("workers must be greater than zero"));
    assert!(output.is_empty());
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("intentional output failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn output_failure_disconnects_all_workers_and_broadcast_reader() {
    let error = completes_without_deadlock(|| {
        let directory = TestDirectory::new();
        let input = directory.requests(&vec![
            json!({"method":"GET", "url":"/alpha"});
            BATCH_REQUEST_LIMIT * 16
        ]);
        let database = directory.database(PATTERNS);
        let shards = Matcher::fast_shards(&database, 8).unwrap();
        run_parallel(
            &input,
            None,
            shards,
            Arc::new(database.rules),
            &mut FailingWriter,
        )
        .unwrap_err()
    });
    assert!(format!("{error:#}").contains("intentional output failure"));
}

#[test]
fn reader_failure_after_broadcast_terminates_all_workers() {
    let error = completes_without_deadlock(|| {
        let directory = TestDirectory::new();
        let input = directory.0.join("broken.json");
        let mut bytes = serde_json::to_vec(&vec![
            json!({"method":"GET", "url":"/alpha"});
            BATCH_REQUEST_LIMIT
        ])
        .unwrap();
        bytes.pop();
        bytes.extend_from_slice(b",invalid JSON]");
        fs::write(&input, bytes).unwrap();
        let database = directory.database(PATTERNS);
        let shards = Matcher::fast_shards(&database, 8).unwrap();
        run_parallel(
            &input,
            None,
            shards,
            Arc::new(database.rules),
            &mut Vec::new(),
        )
        .unwrap_err()
    });
    assert!(format!("{error:#}").contains("read "));
    assert!(format!("{error:#}").contains("broken.json"));
}

#[test]
fn aggregator_rejects_missing_shard_without_emitting_partial_results() {
    let batch = Arc::new(RequestBatch {
        sequence: 0,
        requests: vec![Request {
            id: 0,
            bytes: b"GET /".to_vec(),
        }],
    });
    let (first_sender, first_receiver) = bounded(1);
    first_sender
        .send(PartialBatch {
            batch,
            rule_ids: vec![Vec::new()],
        })
        .unwrap();
    drop(first_sender);
    let (missing_sender, missing_receiver) = bounded(1);
    drop(missing_sender);
    let mut output = Vec::new();
    let error = write_batches(
        &mut output,
        vec![first_receiver, missing_receiver],
        ResultBuilder::new(Arc::new(Vec::new())),
    )
    .unwrap_err();
    assert!(error.to_string().contains("worker 1 stopped"));
    assert!(output.is_empty());
}
