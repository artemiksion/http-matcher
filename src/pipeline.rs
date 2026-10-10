use anyhow::{anyhow, bail, ensure, Context, Result};
use crossbeam_channel::{bounded, Receiver, Sender};
use serde::Serialize;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::thread;

use crate::corpus::{read_requests, ReadStats};
use crate::matcher::{Matcher, RequestResult, ResultBuilder};
use crate::normalize::Request;
use crate::patterns::Rule;

#[cfg(test)]
mod tests;

const BATCH_REQUEST_LIMIT: usize = 256;
const BATCH_BYTE_LIMIT: usize = 1024 * 1024;
const QUEUE_BATCH_LIMIT: usize = 2;

#[derive(Debug, Default, Serialize)]
pub struct RunStats {
    pub requests: usize,
    pub bytes: usize,
    pub matched_requests: usize,
    pub normalization_seconds: f64,
}

impl RunStats {
    fn record(&mut self, request_bytes: usize, result: &RequestResult) {
        self.requests += 1;
        self.bytes += request_bytes;
        self.matched_requests +=
            usize::from(!result.matches.is_empty() || !result.softmatch.is_empty());
    }
}

pub fn run_baseline(
    input_path: &Path,
    request_limit: Option<usize>,
    matcher: &Matcher,
    rules: Arc<Vec<Rule>>,
    output: &mut impl Write,
) -> Result<RunStats> {
    let result_builder = ResultBuilder::new(rules);
    let mut stats = RunStats::default();
    let read_stats = read_requests(input_path, request_limit, |request| {
        let matching_rules = matcher.matching_rules(&request.bytes);
        let result = result_builder.build(request.id, matching_rules);
        write_result(output, &result)?;
        stats.record(request.bytes.len(), &result);
        Ok(())
    })?;
    stats.normalization_seconds = read_stats.normalization_time.as_secs_f64();
    Ok(stats)
}

pub fn run_parallel(
    input_path: &Path,
    request_limit: Option<usize>,
    matchers: Vec<Matcher>,
    rules: Arc<Vec<Rule>>,
    output: &mut impl Write,
) -> Result<RunStats> {
    let workers = matchers.len();
    if workers == 0 {
        bail!("workers must be greater than zero");
    }

    thread::scope(|scope| {
        let mut batch_senders = Vec::with_capacity(workers);
        let mut result_receivers = Vec::with_capacity(workers);
        let mut worker_threads = Vec::with_capacity(workers);
        for matcher in matchers {
            // Independent queues broadcast every batch to every rule shard.
            let (batch_sender, batch_receiver) = bounded(QUEUE_BATCH_LIMIT);
            let (result_sender, result_receiver) = bounded(QUEUE_BATCH_LIMIT);
            batch_senders.push(batch_sender);
            result_receivers.push(result_receiver);
            worker_threads
                .push(scope.spawn(move || process_batches(matcher, batch_receiver, result_sender)));
        }
        let reader = scope.spawn(move || read_batches(input_path, request_limit, batch_senders));

        // Dropping all result receivers on error unblocks workers, then the reader.
        let output_result = write_batches(output, result_receivers, ResultBuilder::new(rules));
        let reader_result = reader.join().map_err(|_| anyhow!("reader thread panicked"));
        let worker_results: Vec<_> = worker_threads
            .into_iter()
            .map(|worker| worker.join().map_err(|_| anyhow!("worker thread panicked")))
            .collect();

        let mut stats = output_result?;
        let read_stats = reader_result??;
        for worker_result in worker_results {
            worker_result??;
        }
        if stats.requests != read_stats.requests {
            bail!(
                "read {} requests but wrote {} results",
                read_stats.requests,
                stats.requests
            );
        }
        stats.normalization_seconds = read_stats.normalization_time.as_secs_f64();
        Ok(stats)
    })
}

fn read_batches(
    input_path: &Path,
    request_limit: Option<usize>,
    batch_senders: Vec<Sender<Arc<RequestBatch>>>,
) -> Result<ReadStats> {
    let mut batch = Vec::with_capacity(BATCH_REQUEST_LIMIT);
    let mut batch_bytes = 0;
    let mut sequence = 0;
    let read_stats = read_requests(input_path, request_limit, |request| {
        if !batch.is_empty() && batch_bytes + request.bytes.len() > BATCH_BYTE_LIMIT {
            broadcast_batch(&batch_senders, sequence, std::mem::take(&mut batch))?;
            sequence += 1;
            batch_bytes = 0;
        }
        batch_bytes += request.bytes.len();
        batch.push(request);
        if batch.len() == BATCH_REQUEST_LIMIT || batch_bytes >= BATCH_BYTE_LIMIT {
            broadcast_batch(&batch_senders, sequence, std::mem::take(&mut batch))?;
            sequence += 1;
            batch_bytes = 0;
        }
        Ok(())
    })?;
    if !batch.is_empty() {
        broadcast_batch(&batch_senders, sequence, batch)?;
    }
    Ok(read_stats)
}

struct RequestBatch {
    sequence: usize,
    requests: Vec<Request>,
}

fn broadcast_batch(
    senders: &[Sender<Arc<RequestBatch>>],
    sequence: usize,
    requests: Vec<Request>,
) -> Result<()> {
    let batch = Arc::new(RequestBatch { sequence, requests });
    for (worker_id, sender) in senders.iter().enumerate() {
        sender
            .send(Arc::clone(&batch))
            .with_context(|| format!("worker {worker_id} stopped receiving batch {sequence}"))?;
    }
    Ok(())
}

struct PartialBatch {
    batch: Arc<RequestBatch>,
    rule_ids: Vec<Vec<usize>>,
}

fn process_batches(
    matcher: Matcher,
    batch_receiver: Receiver<Arc<RequestBatch>>,
    result_sender: Sender<PartialBatch>,
) -> Result<()> {
    for batch in batch_receiver {
        let rule_ids = batch
            .requests
            .iter()
            .map(|request| matcher.matching_rules(&request.bytes))
            .collect();
        result_sender.send(PartialBatch { batch, rule_ids })?;
    }
    Ok(())
}

fn write_batches(
    output: &mut impl Write,
    result_receivers: Vec<Receiver<PartialBatch>>,
    result_builder: ResultBuilder,
) -> Result<RunStats> {
    let mut stats = RunStats::default();
    let mut sequence = 0;
    while let Ok(mut combined) = result_receivers[0].recv() {
        ensure!(
            combined.batch.sequence == sequence,
            "unexpected batch order"
        );
        ensure!(
            combined.rule_ids.len() == combined.batch.requests.len(),
            "incomplete result from worker 0 for batch {sequence}"
        );
        // FIFO per-worker channels bound pending results even if one shard is slow.
        for (worker_id, receiver) in result_receivers.iter().enumerate().skip(1) {
            let partial = receiver.recv().with_context(|| {
                format!("worker {worker_id} stopped before completing batch {sequence}")
            })?;
            ensure!(
                Arc::ptr_eq(&combined.batch, &partial.batch),
                "worker {worker_id} returned a different batch at sequence {sequence}"
            );
            ensure!(
                partial.rule_ids.len() == combined.rule_ids.len(),
                "incomplete result from worker {worker_id} for batch {sequence}"
            );
            for (all_ids, shard_ids) in combined.rule_ids.iter_mut().zip(partial.rule_ids) {
                all_ids.extend(shard_ids);
            }
        }
        // Service priority and hard/soft precedence apply only after all shards reply.
        for (request, rule_ids) in combined.batch.requests.iter().zip(combined.rule_ids) {
            let result = result_builder.build(request.id, rule_ids);
            write_result(output, &result)?;
            stats.record(request.bytes.len(), &result);
        }
        sequence += 1;
    }
    for (worker_id, receiver) in result_receivers.iter().enumerate().skip(1) {
        ensure!(
            receiver.recv().is_err(),
            "worker {worker_id} returned more batches than worker 0"
        );
    }
    Ok(stats)
}

fn write_result(output: &mut impl Write, result: &RequestResult) -> Result<()> {
    serde_json::to_writer(&mut *output, result)?;
    output.write_all(b"\n")?;
    Ok(())
}
