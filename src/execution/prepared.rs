use std::ops::Range;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, OnceLock};
use std::thread;
use std::time::Instant;

use anyhow::{anyhow, ensure, Context, Result};
use crossbeam_channel::bounded;
use serde::Serialize;

use crate::input::{read_requests, Request, Rule};
use crate::matcher::{Matcher, RequestResult, ResultBuilder};
use crate::reporting::{GroupDescription, MatchingTime, StageClock};

use super::stats::RunStats;

const BATCH_REQUEST_LIMIT: usize = 32;
const BATCH_BYTE_LIMIT: usize = 64 * 1024;

pub struct PreparedCorpus {
    requests: Vec<Request>,
    batches: Vec<Range<usize>>,
    pub normalized_bytes: usize,
    pub storage_bytes: usize,
    pub normalization_seconds: f64,
}

impl PreparedCorpus {
    pub fn load(input: &Path, limit: Option<usize>) -> Result<Self> {
        let mut requests = Vec::new();
        let mut normalized_bytes = 0usize;
        let mut byte_capacity = 0usize;
        let stats = read_requests(input, limit, |request| {
            ensure!(
                request.id == requests.len() as u64,
                "non-sequential prepared request ID"
            );
            normalized_bytes = normalized_bytes
                .checked_add(request.bytes.len())
                .context("prepared corpus too large")?;
            byte_capacity = byte_capacity
                .checked_add(request.bytes.capacity())
                .context("prepared corpus capacity overflow")?;
            requests.push(request);
            Ok(())
        })?;
        ensure!(
            stats.requests == requests.len(),
            "prepared reader count mismatch"
        );
        requests.shrink_to_fit();
        let batches = plan_batches(&requests);
        let storage_bytes = byte_capacity
            + requests.capacity() * std::mem::size_of::<Request>()
            + batches.capacity() * std::mem::size_of::<Range<usize>>();
        Ok(Self {
            requests,
            batches,
            normalized_bytes,
            storage_bytes,
            normalization_seconds: stats.normalization_time.as_secs_f64(),
        })
    }

    pub fn len(&self) -> usize {
        self.requests.len()
    }
}

fn plan_batches(requests: &[Request]) -> Vec<Range<usize>> {
    let mut batches = Vec::new();
    let mut first = 0;
    let mut bytes = 0;
    for (index, request) in requests.iter().enumerate() {
        if index > first
            && (index - first == BATCH_REQUEST_LIMIT
                || request.bytes.len() > BATCH_BYTE_LIMIT.saturating_sub(bytes))
        {
            batches.push(first..index);
            first = index;
            bytes = 0;
        }
        bytes += request.bytes.len();
        if bytes >= BATCH_BYTE_LIMIT {
            batches.push(first..index + 1);
            first = index + 1;
            bytes = 0;
        }
    }
    if first < requests.len() {
        batches.push(first..requests.len());
    }
    batches
}

#[derive(Serialize)]
pub struct PreparedWorker {
    worker_id: usize,
    requests: usize,
    bytes: usize,
    batches: usize,
    wall_seconds: f64,
    cpu_seconds: Option<f64>,
}

#[derive(Serialize)]
pub struct PreparedMetrics {
    pub corpus_prepare_seconds: f64,
    pub worker_setup_seconds: f64,
    pub matching_seconds: f64,
    pub matching_throughput_req_s: f64,
    pub postprocess_seconds: f64,
    pub output_seconds: f64,
    pub storage_bytes: usize,
    pub batches: usize,
    pub workers: Vec<PreparedWorker>,
}

pub struct PreparedRun {
    pub results: Vec<RequestResult>,
    pub stats: RunStats,
    pub metrics: PreparedMetrics,
    pub diagnostics: Option<PreparedDiagnosticReport>,
}

#[derive(Serialize)]
pub struct PreparedDiagnosticReport {
    method: &'static str,
    groups: Vec<GroupDescription>,
    workers: Vec<PreparedMatchingReport>,
}

#[derive(Serialize)]
struct PreparedMatchingReport {
    worker_id: usize,
    matching: MatchingTime,
}

pub fn run_prepared(
    corpus: &PreparedCorpus,
    matchers: Vec<Matcher>,
    rules: Arc<Vec<Rule>>,
) -> Result<PreparedRun> {
    run_prepared_inner::<false>(corpus, matchers, rules)
}

pub fn run_prepared_diagnostic(
    corpus: &PreparedCorpus,
    matchers: Vec<Matcher>,
    rules: Arc<Vec<Rule>>,
) -> Result<PreparedRun> {
    run_prepared_inner::<true>(corpus, matchers, rules)
}

fn run_prepared_inner<const DIAG: bool>(
    corpus: &PreparedCorpus,
    matchers: Vec<Matcher>,
    rules: Arc<Vec<Rule>>,
) -> Result<PreparedRun> {
    ensure!(!matchers.is_empty(), "workers must be greater than zero");
    let groups = if DIAG {
        matchers[0].group_descriptions(&rules)?
    } else {
        Vec::new()
    };
    let setup_start = Instant::now();
    let workers = matchers.len();
    let results: Vec<OnceLock<RequestResult>> =
        (0..corpus.len()).map(|_| OnceLock::new()).collect();
    let next_batch = AtomicUsize::new(0);
    let start_barrier = Barrier::new(workers + 1);
    let end_barrier = Barrier::new(workers + 1);
    let (ready_sender, ready_receiver) = bounded(workers);

    let (stats, mut metrics, matching_reports, postprocess_start) = thread::scope(|scope| {
        let mut threads = Vec::with_capacity(workers);
        for (worker_id, matcher) in matchers.into_iter().enumerate() {
            let ready = ready_sender.clone();
            let builder = ResultBuilder::new(Arc::clone(&rules));
            let mut timing = if DIAG {
                MatchingTime::new(groups.len())
            } else {
                MatchingTime::default()
            };
            let slots = &results;
            let next = &next_batch;
            let start = &start_barrier;
            let end = &end_barrier;
            threads.push(scope.spawn(move || {
                ready.send(()).expect("ready receiver remains alive");
                start.wait();
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    let clock = StageClock::start();
                    let mut stats = RunStats::default();
                    let mut batches = 0;
                    loop {
                        let batch_id = next.fetch_add(1, Ordering::Relaxed);
                        let Some(batch) = corpus.batches.get(batch_id) else {
                            break;
                        };
                        batches += 1;
                        for index in batch.clone() {
                            let request = &corpus.requests[index];
                            // Literal routing, all rule checks and complete service
                            // priority/deduplication are inside the measured work.
                            let ids = if DIAG {
                                matcher.matching_rules_diagnostic(
                                    &request.bytes,
                                    request.id,
                                    &mut timing,
                                )
                            } else {
                                matcher.matching_rules(&request.bytes)
                            };
                            let build_start = DIAG.then(Instant::now);
                            let result = builder.build(request.id, ids);
                            if let Some(start) = build_start {
                                timing.result_build_seconds += start.elapsed().as_secs_f64();
                            }
                            stats.record(request.bytes.len(), &result);
                            assert!(
                                slots[index].set(result).is_ok(),
                                "duplicate prepared result"
                            );
                        }
                    }
                    let stage = clock.finish();
                    let report = PreparedWorker {
                        worker_id,
                        requests: stats.requests,
                        bytes: stats.bytes,
                        batches,
                        wall_seconds: stage.wall_seconds,
                        cpu_seconds: stage.cpu_seconds,
                    };
                    (stats, report, timing)
                }));
                // Even a panicking matcher must release the completion barrier.
                end.wait();
                outcome.map_err(|_| anyhow!("prepared worker {worker_id} panicked"))
            }));
        }
        drop(ready_sender);
        for _ in 0..workers {
            ready_receiver
                .recv()
                .context("prepared worker did not become ready")?;
        }
        let worker_setup_seconds = setup_start.elapsed().as_secs_f64();
        let matching_start = Instant::now();
        start_barrier.wait();
        end_barrier.wait();
        let matching_seconds = matching_start.elapsed().as_secs_f64();

        let postprocess_start = Instant::now();
        let mut stats = RunStats::default();
        let mut worker_reports = Vec::with_capacity(workers);
        let mut matching_reports = Vec::new();
        for worker in threads {
            let (worker_stats, report, matching) = worker
                .join()
                .map_err(|_| anyhow!("prepared worker thread panicked"))??;
            stats.requests += worker_stats.requests;
            stats.bytes += worker_stats.bytes;
            stats.matched_requests += worker_stats.matched_requests;
            if DIAG {
                matching_reports.push(PreparedMatchingReport {
                    worker_id: report.worker_id,
                    matching,
                });
            }
            worker_reports.push(report);
        }
        ensure!(
            stats.requests == corpus.len() && stats.bytes == corpus.normalized_bytes,
            "incomplete prepared results"
        );
        stats.normalization_seconds = corpus.normalization_seconds;
        Ok::<_, anyhow::Error>((
            stats,
            PreparedMetrics {
                corpus_prepare_seconds: 0.0,
                worker_setup_seconds,
                matching_seconds,
                matching_throughput_req_s: corpus.len() as f64 / matching_seconds,
                postprocess_seconds: 0.0,
                output_seconds: 0.0,
                storage_bytes: corpus.storage_bytes,
                batches: corpus.batches.len(),
                workers: worker_reports,
            },
            matching_reports,
            postprocess_start,
        ))
    })?;
    let results = results
        .into_iter()
        .map(|slot| slot.into_inner().context("missing prepared result"))
        .collect::<Result<Vec<_>>>()?;
    metrics.postprocess_seconds = postprocess_start.elapsed().as_secs_f64();
    Ok(PreparedRun {
        results,
        stats,
        metrics,
        diagnostics: DIAG.then_some(PreparedDiagnosticReport {
            method: "Same prepared corpus, complete matcher replicas, batch scheduler and timing boundaries as ordinary prepared runs. Per-request filters, group engines and result construction are timed with Instant. Group times include descheduling; sums across workers are not elapsed wall-clock. Per-stage CPU clocks are reported in prepared worker metrics. Diagnostic timers and occurrence accounting perturb performance; use ordinary prepared runs for throughput. No file I/O, JSON decoding, normalization or serialization occurs in the matching interval.",
            groups,
            workers: matching_reports,
        }),
    })
}

#[cfg(test)]
mod tests;
