//! Request, byte and match counters aggregated across workers.

use serde::Serialize;

use crate::matcher::RequestResult;

#[derive(Debug, Default, Serialize)]
pub struct RunStats {
    pub requests: usize,
    pub bytes: usize,
    pub matched_requests: usize,
    pub normalization_seconds: f64,
}

impl RunStats {
    pub(super) fn record(&mut self, request_bytes: usize, result: &RequestResult) {
        self.requests += 1;
        self.bytes += request_bytes;
        self.matched_requests +=
            usize::from(!result.matches.is_empty() || !result.softmatch.is_empty());
    }
}
