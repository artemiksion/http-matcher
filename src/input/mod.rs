//! Read the request corpus and signature rules, and normalize request bytes.

mod corpus;
mod normalize;
mod patterns;

pub(crate) use corpus::{collect_json_files, read_requests};
pub(crate) use normalize::Request;
pub(crate) use patterns::{MatchKind, PatternDatabase, Rule, PATTERNS_PATH};
