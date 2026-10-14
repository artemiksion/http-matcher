use super::*;
use crate::input::PatternDatabase;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn byte_limited_batches_cover_every_request_and_isolate_oversized_inputs() {
    let requests: Vec<_> = [0, 1, 100, BATCH_BYTE_LIMIT, BATCH_BYTE_LIMIT + 1, 3]
        .into_iter()
        .enumerate()
        .map(|(id, length)| Request {
            id: id as u64,
            bytes: vec![0; length],
        })
        .collect();
    let batches = plan_batches(&requests);
    let indices: Vec<_> = batches.iter().flat_map(Clone::clone).collect();
    assert_eq!(indices, (0..requests.len()).collect::<Vec<_>>());
    assert!(batches.contains(&(3..4)));
    assert!(batches.contains(&(4..5)));
    for batch in batches {
        assert!(batch.len() <= BATCH_REQUEST_LIMIT);
        assert!(
            batch.len() == 1
                || batch
                    .clone()
                    .map(|i| requests[i].bytes.len())
                    .sum::<usize>()
                    <= BATCH_BYTE_LIMIT
        );
    }
    assert!(plan_batches(&[]).is_empty());
}

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

#[test]
fn prepared_runs_match_baseline_after_input_is_removed_and_preserve_limits() {
    let directory = TestDirectory::new();
    let patterns = format!("{PATTERNS}match mongo m|^.*version.....([\\.\\d]+)|s\nmatch duo m|^.........(.*)\\x00|s\nmatch length m|^.{{111}}|s\nmatch overlap m|^.*aa[b]+|s\n");
    let database = directory.database(&patterns);
    let rules = Arc::new(database.rules.clone());
    let baseline = Matcher::baseline(&database);
    let requests: Vec<_> = (0..97).map(|i| json!({"method":"GET", "url":"/alpha", "data":if i%2 == 0 { "version-----X version-----1\u{0}".into() } else { format!("aaab{}", "x".repeat(if i == 1 { 100_000 } else { i })) }})).collect();
    for limit in [None, Some(33), Some(0)] {
        let input = directory.requests(&requests);
        let corpus = PreparedCorpus::load(&input, limit).unwrap();
        let builder = ResultBuilder::new(Arc::clone(&rules));
        let expected: Vec<_> = corpus
            .requests
            .iter()
            .map(|request| builder.build(request.id, baseline.matching_rules(&request.bytes)))
            .collect();
        fs::remove_file(&input).unwrap();
        let prepared_baseline = run_prepared(
            &corpus,
            vec![Matcher::baseline(&database)],
            Arc::clone(&rules),
        )
        .unwrap();
        assert_eq!(prepared_baseline.results, expected);
        assert!(prepared_baseline.diagnostics.is_none());
        assert!(run_prepared(&corpus, Vec::new(), Arc::clone(&rules)).is_err());
        for workers in [1, 2, 4, 8] {
            let matchers = Matcher::fast_replicas(&database, workers).unwrap();
            for matcher in &matchers {
                let bytes = b"GET /\r\n\r\naaab version-----X version-----2\0";
                assert_eq!(
                    matcher.matching_rules(bytes),
                    baseline.matching_rules(bytes)
                );
            }
            let run = if workers == 2 {
                run_prepared_diagnostic(&corpus, matchers, Arc::clone(&rules)).unwrap()
            } else {
                run_prepared(&corpus, matchers, Arc::clone(&rules)).unwrap()
            };
            assert_eq!(run.diagnostics.is_some(), workers == 2);
            assert_eq!(run.results, expected);
            assert_eq!(run.stats.requests, corpus.len());
            assert_eq!(run.stats.bytes, corpus.normalized_bytes);
            assert_eq!(
                run.stats.matched_requests,
                prepared_baseline.stats.matched_requests
            );
            assert!(run.metrics.matching_seconds > 0.0);
            assert_eq!(run.metrics.workers.len(), workers);
            assert_eq!(
                run.metrics
                    .workers
                    .iter()
                    .map(|w| w.requests)
                    .sum::<usize>(),
                corpus.len()
            );
            assert_eq!(
                run.metrics.workers.iter().map(|w| w.bytes).sum::<usize>(),
                corpus.normalized_bytes
            );
            assert_eq!(
                run.metrics.workers.iter().map(|w| w.batches).sum::<usize>(),
                corpus.batches.len()
            );
        }
    }
}
