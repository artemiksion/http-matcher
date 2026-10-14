//! Prepare in-memory batches and run them through dynamically scheduled workers.

mod prepared;
mod stats;

pub(crate) use prepared::{run_prepared, run_prepared_diagnostic, PreparedCorpus, PreparedMetrics};
pub(crate) use stats::RunStats;
