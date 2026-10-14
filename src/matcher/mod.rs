//! Baseline and fast matching, with shared service priority and deduplication.

use anyhow::Result;
use regex::bytes::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::Arc;

use crate::input::{MatchKind, PatternDatabase, Rule};
use crate::reporting::{GroupDescription, MatchingTime};

mod grouped;
use grouped::GroupedMatcher;

pub enum Matcher {
    Baseline(Vec<Regex>),
    Fast(Box<GroupedMatcher>),
}

impl Matcher {
    pub fn baseline(database: &PatternDatabase) -> Self {
        Self::Baseline(database.regexes.clone())
    }

    pub fn fast_replicas(database: &PatternDatabase, workers: usize) -> Result<Vec<Self>> {
        Ok(GroupedMatcher::replicas(&database.rules, workers)?
            .into_iter()
            .map(|matcher| Self::Fast(Box::new(matcher)))
            .collect())
    }

    pub fn matching_rules(&self, request_bytes: &[u8]) -> Vec<usize> {
        match self {
            Self::Baseline(regexes) => regexes
                .iter()
                .enumerate()
                .filter_map(|(rule_id, regex)| regex.is_match(request_bytes).then_some(rule_id))
                .collect(),
            Self::Fast(matcher) => matcher.matching_rules(request_bytes),
        }
    }

    pub fn group_descriptions(&self, rules: &[Rule]) -> Result<Vec<GroupDescription>> {
        match self {
            Self::Fast(matcher) => Ok(matcher.group_descriptions(rules)),
            Self::Baseline(_) => anyhow::bail!("diagnostics requires fast mode"),
        }
    }

    pub fn matching_rules_diagnostic(
        &self,
        bytes: &[u8],
        request_id: u64,
        timing: &mut MatchingTime,
    ) -> Vec<usize> {
        match self {
            Self::Fast(matcher) => matcher.matching_rules_diagnostic(bytes, request_id, timing),
            Self::Baseline(_) => {
                unreachable!("diagnostic matcher was validated before starting workers")
            }
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
