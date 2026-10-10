use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

mod corpus;
mod matcher;
mod normalize;
mod patterns;
mod pipeline;

use matcher::Matcher;
use patterns::{PatternDatabase, PATTERNS_PATH};
use pipeline::{run_baseline, run_parallel, RunStats};

#[derive(Clone, Copy, Debug, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Baseline,
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
}

fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let workers = worker_count(&arguments)?;
    validate_output_path(&arguments.input, &arguments.output)?;
    let total_start = Instant::now();
    let database = PatternDatabase::load(Path::new(PATTERNS_PATH))
        .with_context(|| format!("could not load {PATTERNS_PATH}"))?;
    let supported_patterns = database.rules.len();
    let skipped_patterns = database.skipped.len();
    if supported_patterns == 0 {
        bail!("no supported patterns found in {PATTERNS_PATH}");
    }

    let matchers = match arguments.mode {
        Mode::Baseline => vec![Matcher::baseline(&database)],
        Mode::Fast => Matcher::fast_shards(&database, workers)?,
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
    let preparation_seconds = total_start.elapsed().as_secs_f64();
    let pipeline_start = Instant::now();

    let stats = match arguments.mode {
        Mode::Baseline => run_baseline(
            &arguments.input,
            arguments.limit,
            &matchers[0],
            rules,
            &mut output,
        )?,
        Mode::Fast => run_parallel(
            &arguments.input,
            arguments.limit,
            matchers,
            rules,
            &mut output,
        )?,
    };
    output.flush()?;
    let pipeline_seconds = pipeline_start.elapsed().as_secs_f64();
    let total_seconds = total_start.elapsed().as_secs_f64();
    let throughput_req_s = stats.requests as f64 / total_seconds;
    let metrics = Metrics {
        mode: arguments.mode,
        workers,
        supported_patterns,
        skipped_patterns,
        stats,
        preparation_seconds,
        pipeline_seconds,
        total_seconds,
        throughput_req_s,
    };
    eprintln!("{}", serde_json::to_string_pretty(&metrics)?);
    Ok(())
}

fn worker_count(arguments: &Arguments) -> Result<usize> {
    match arguments.mode {
        Mode::Baseline => {
            if arguments.workers.is_some_and(|workers| workers != 1) {
                bail!("baseline always uses one worker");
            }
            Ok(1)
        }
        Mode::Fast => {
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
    }
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

fn validate_output_path(input: &Path, output: &Path) -> Result<()> {
    let input_path = input
        .canonicalize()
        .with_context(|| format!("could not find input {}", input.display()))?;
    let patterns_path = Path::new(PATTERNS_PATH).canonicalize().ok();
    for candidate in [output.to_owned(), output.with_extension("skipped.jsonl")] {
        if let Ok(output_path) = candidate.canonicalize() {
            if output_path == input_path || Some(output_path) == patterns_path {
                bail!("output must be separate from the input and the pattern database");
            }
        }
    }
    if input_path.is_dir()
        && output
            .extension()
            .is_some_and(|extension| extension == "json")
    {
        bail!("use a .jsonl output file to keep results separate from JSON corpus files");
    }
    Ok(())
}
