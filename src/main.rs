use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

mod execution;
mod input;
mod matcher;
mod reporting;

use execution::{run_prepared, run_prepared_diagnostic, PreparedCorpus, PreparedMetrics, RunStats};
use input::{PatternDatabase, PATTERNS_PATH};
use matcher::Matcher;
use reporting::{validate_destinations, validate_output_paths};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    #[value(alias = "prepared-baseline")]
    Baseline,
    #[value(alias = "prepared")]
    Fast,
}

#[derive(Parser)]
#[command(about = "Match saved HTTP requests against Nmap signatures")]
struct Arguments {
    #[arg(long, value_enum, default_value = "fast")]
    mode: Mode,
    #[arg(long)]
    workers: Option<usize>,
    #[arg(long)]
    limit: Option<usize>,
    #[arg(long, default_value = "data/requests")]
    input: PathBuf,
    #[arg(long, default_value = "results/matches.jsonl")]
    output: PathBuf,
    #[arg(long, help = "Collect filter and rule timings for fast mode")]
    diagnostics: bool,
}

#[derive(Serialize)]
struct Metrics {
    mode: Mode,
    workers: usize,
    supported_patterns: usize,
    skipped_patterns: usize,
    #[serde(flatten)]
    stats: RunStats,
    preparation_seconds: f64,
    pipeline_seconds: f64,
    total_seconds: f64,
    throughput_req_s: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostics_path: Option<PathBuf>,
    prepared: PreparedMetrics,
}

fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let workers = worker_count(&arguments)?;
    if arguments.diagnostics && arguments.mode == Mode::Baseline {
        bail!("--diagnostics requires --mode fast");
    }
    let total_start = Instant::now();
    validate_output_paths(
        &arguments.input,
        Path::new(PATTERNS_PATH),
        &arguments.output,
    )?;
    let diagnostics_path = if arguments.diagnostics {
        let path = arguments.output.with_extension("diagnostics.json");
        validate_destinations(
            &arguments.input,
            Path::new(PATTERNS_PATH),
            &[
                arguments.output.clone(),
                arguments.output.with_extension("skipped.jsonl"),
                path.clone(),
            ],
        )?;
        Some(path)
    } else {
        None
    };
    let database = PatternDatabase::load(Path::new(PATTERNS_PATH))
        .with_context(|| format!("could not load {PATTERNS_PATH}"))?;
    let supported_patterns = database.rules.len();
    let skipped_patterns = database.skipped.len();
    if supported_patterns == 0 {
        bail!("no supported patterns found in {PATTERNS_PATH}");
    }
    let matchers = match arguments.mode {
        Mode::Baseline => vec![Matcher::baseline(&database)],
        Mode::Fast => Matcher::fast_replicas(&database, workers)?,
    };
    let mut output = create_output(&arguments.output)?;
    let skipped_path = arguments.output.with_extension("skipped.jsonl");
    let mut skipped_output = create_output(&skipped_path)?;
    for skipped in &database.skipped {
        serde_json::to_writer(&mut skipped_output, skipped)?;
        skipped_output.write_all(b"\n")?;
    }
    skipped_output.flush()?;

    let rules = Arc::new(database.rules);
    drop(database.regexes);
    let corpus_start = Instant::now();
    let corpus = PreparedCorpus::load(&arguments.input, arguments.limit)?;
    let corpus_prepare_seconds = corpus_start.elapsed().as_secs_f64();
    let preparation_seconds = total_start.elapsed().as_secs_f64();
    let pipeline_start = Instant::now();
    let mut run = if arguments.diagnostics {
        run_prepared_diagnostic(&corpus, matchers, rules)?
    } else {
        run_prepared(&corpus, matchers, rules)?
    };
    // Processing ends at the workers' completion barrier. Serialization,
    // writing and flushing are measured separately for both algorithms.
    let output_start = Instant::now();
    for result in &run.results {
        serde_json::to_writer(&mut output, result)?;
        output.write_all(b"\n")?;
    }
    output.flush()?;
    run.metrics.corpus_prepare_seconds = corpus_prepare_seconds;
    run.metrics.output_seconds = output_start.elapsed().as_secs_f64();
    if let Some(diagnostics) = run.diagnostics {
        let path = diagnostics_path
            .as_ref()
            .context("missing diagnostic path")?;
        let mut report_output = create_output(path)?;
        serde_json::to_writer_pretty(&mut report_output, &diagnostics)?;
        report_output.write_all(b"\n")?;
        report_output.flush()?;
    }
    let pipeline_seconds = pipeline_start.elapsed().as_secs_f64();
    let total_seconds = total_start.elapsed().as_secs_f64();
    let throughput_req_s = run.stats.requests as f64 / total_seconds;
    let metrics = Metrics {
        mode: arguments.mode,
        workers,
        supported_patterns,
        skipped_patterns,
        stats: run.stats,
        preparation_seconds,
        pipeline_seconds,
        total_seconds,
        throughput_req_s,
        diagnostics_path,
        prepared: run.metrics,
    };
    eprintln!("{}", serde_json::to_string_pretty(&metrics)?);
    Ok(())
}

fn worker_count(arguments: &Arguments) -> Result<usize> {
    if arguments.mode == Mode::Baseline {
        if arguments.workers.is_some_and(|workers| workers != 1) {
            bail!("baseline always uses one worker");
        }
        return Ok(1);
    }
    let workers = arguments.workers.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
    });
    if workers == 0 {
        bail!("workers must be greater than zero");
    }
    Ok(workers)
}

fn create_output(path: &Path) -> Result<BufWriter<File>> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let file =
        File::create(path).with_context(|| format!("could not create {}", path.display()))?;
    Ok(BufWriter::new(file))
}
