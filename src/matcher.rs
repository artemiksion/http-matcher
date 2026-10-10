use anyhow::{ensure, Context, Result};
use regex::bytes::{Regex, RegexSet, RegexSetBuilder};
use serde::Serialize;
use std::collections::HashSet;
use std::sync::Arc;

use crate::patterns::{MatchKind, PatternDatabase, Rule};

const SET_SIZE_LIMIT: usize = 256 * 1024 * 1024;
// On the malicious corpus, 128 MiB was faster than 64; 256 showed no clear gain.
const DFA_CACHE_LIMIT: usize = 128 * 1024 * 1024;

pub enum Matcher {
    Baseline(Vec<Regex>),
    Fast {
        regex_set: RegexSet,
        first_rule_id: usize,
    },
}

impl Matcher {
    pub fn baseline(database: &PatternDatabase) -> Self {
        Self::Baseline(database.regexes.clone())
    }

    pub fn fast_shards(database: &PatternDatabase, workers: usize) -> Result<Vec<Self>> {
        ensure!(workers > 0, "workers must be greater than zero");
        let rules_per_worker = database.rules.len() / workers;
        let remainder = database.rules.len() % workers;
        let mut first_rule_id = 0;
        let mut matchers = Vec::with_capacity(workers);
        for worker_id in 0..workers {
            let count = rules_per_worker + usize::from(worker_id < remainder);
            let end = first_rule_id + count;
            let expressions = database.rules[first_rule_id..end]
                .iter()
                .map(|rule| &rule.expression);
            let regex_set = RegexSetBuilder::new(expressions)
                .unicode(false)
                .size_limit(SET_SIZE_LIMIT)
                .dfa_size_limit(DFA_CACHE_LIMIT)
                .build()
                .with_context(|| format!("could not compile regex shard {worker_id}"))?;
            matchers.push(Self::Fast {
                regex_set,
                first_rule_id,
            });
            first_rule_id = end;
        }
        Ok(matchers)
    }

    pub fn matching_rules(&self, request_bytes: &[u8]) -> Vec<usize> {
        match self {
            Self::Baseline(regexes) => regexes
                .iter()
                .enumerate()
                .filter_map(|(rule_id, regex)| regex.is_match(request_bytes).then_some(rule_id))
                .collect(),
            Self::Fast {
                regex_set,
                first_rule_id,
            } => regex_set
                .matches(request_bytes)
                .iter()
                .map(|local_id| first_rule_id + local_id)
                .collect(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct RequestResult {
    pub request_id: u64,
    #[serde(rename = "match")]
    pub matches: Vec<String>,
    pub softmatch: Vec<String>,
}

pub struct ResultBuilder {
    rules: Arc<Vec<Rule>>,
}

impl ResultBuilder {
    pub fn new(rules: Arc<Vec<Rule>>) -> Self {
        Self { rules }
    }

    pub fn build(&self, request_id: u64, rule_ids: Vec<usize>) -> RequestResult {
        let mut matched_rules: Vec<_> = rule_ids.iter().map(|&id| &self.rules[id]).collect();
        matched_rules.sort_unstable_by_key(|rule| (rule.probe_order, rule.line_number));

        let mut matches = Vec::new();
        let mut softmatch = Vec::new();
        let mut hard_services = HashSet::new();
        let mut soft_services = HashSet::new();

        for rule in &matched_rules {
            if rule.kind == MatchKind::Match && hard_services.insert(rule.service.as_str()) {
                matches.push(rule.service.clone());
            }
        }
        for rule in &matched_rules {
            if rule.kind == MatchKind::Softmatch
                && !hard_services.contains(rule.service.as_str())
                && soft_services.insert(rule.service.as_str())
            {
                softmatch.push(rule.service.clone());
            }
        }

        RequestResult {
            request_id,
            matches,
            softmatch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(service: &str, kind: MatchKind, probe_order: usize, expression: &str) -> Rule {
        Rule {
            service: service.into(),
            kind,
            probe_order,
            line_number: probe_order + 1,
            expression: expression.into(),
        }
    }

    #[test]
    fn results_prefer_hard_matches_and_preserve_probe_priority() {
        let rules = Arc::new(vec![
            rule("http", MatchKind::Softmatch, 0, "http"),
            rule("ssh", MatchKind::Match, 2, "ssh"),
            rule("http", MatchKind::Match, 1, "http"),
            rule("smtp", MatchKind::Softmatch, 3, "smtp"),
            rule("http", MatchKind::Match, 4, "http"),
        ]);
        let builder = ResultBuilder::new(rules);
        let result = builder.build(7, vec![4, 3, 2, 1, 0]);
        assert_eq!(result.matches, ["http", "ssh"]);
        assert_eq!(result.softmatch, ["smtp"]);
        assert_eq!(result.request_id, 7);
    }
}
