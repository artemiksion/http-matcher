//! Performance diagnostics and validation of output destinations.

mod diagnostics;
mod output;

pub(crate) use diagnostics::{GroupDescription, MatchingTime, RuleDescription, StageClock};
pub(crate) use output::{validate_destinations, validate_output_paths};
