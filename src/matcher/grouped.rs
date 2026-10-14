use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{ensure, Context, Result};
use memchr::memmem::Finder;
use regex::bytes::{RegexSet, RegexSetBuilder};
use regex_syntax::hir::literal::ExtractKind;
use regex_syntax::hir::Look;
use regex_syntax::ParserBuilder;

use crate::input::Rule;
use crate::reporting::{GroupDescription, MatchingTime, RuleDescription};
mod guards;
use guards::{extract_literals, mark, ByteSet, PrefixIndex, RuleGuard};

mod primitives;
use primitives::{selective_literals, LiteralTail, Primitive};
mod literals;
use literals::{CandidateScratch, LiteralCandidates};

#[cfg(test)]
mod tests;

// Initial tuning values; group size and routing do not depend on worker count.
const MAX_GROUP_RULES: usize = 128;
const GROUP_PREFIX_BYTES: usize = 4;
const SET_SIZE_LIMIT: usize = 256 * 1024 * 1024;
const DFA_CACHE_BUDGET_PER_WORKER: usize = 128 * 1024 * 1024;
const MAX_GROUP_DFA_CACHE: usize = 8 * 1024 * 1024;
const EMPTY_INPUT_BUCKET: usize = 256;

pub struct GroupedMatcher {
    groups: Vec<RegexGroup>,
    index: Arc<GroupIndex>,
    // Each worker owns its search caches and scratch.
    scratch: RefCell<SearchScratch>,
}

struct GroupIndex {
    prefixes: PrefixIndex,
    fallback: Vec<Vec<usize>>,
    literal_search: Option<Box<LiteralCandidates>>,
    literal_groups: Vec<Vec<usize>>,
    literal_first_bytes: ByteSet,
}

#[derive(Clone)]
struct RegexGroup {
    engine: GroupEngine,
    // Grouping changes rule order, so set-local IDs need an explicit mapping.
    rule_ids: Arc<[usize]>,
    guard: RuleGuard,
}

#[derive(Clone)]
enum GroupEngine {
    Regex(RegexSet),
    Single(RegexSet),
    Primitive(Primitive),
    LiteralTail {
        predicate: LiteralTail,
        finder: Finder<'static>,
    },
}

struct SearchScratch {
    selected_groups: Vec<u64>,
    seen_literals: Vec<u64>,
    literal_candidates: CandidateScratch,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum GroupCondition {
    // The alternatives in a condition are ORed. Every rule needs at least one.
    Prefixes(Vec<Vec<u8>>),
    Literals(Vec<Vec<u8>>),
    FirstBytes(ByteSet),
    Primitive(Primitive),
    LiteralTail(LiteralTail),
}

struct GroupPlan {
    condition: GroupCondition,
    rule_ids: Vec<usize>,
    guard: RuleGuard,
}

impl GroupedMatcher {
    pub fn replicas(rules: &[Rule], workers: usize) -> Result<Vec<Self>> {
        ensure!(workers > 0, "workers must be greater than zero");
        let matcher = Self::new(rules, plan_groups(rules)?)?;
        let mut replicas = Vec::with_capacity(workers);
        for _ in 1..workers {
            replicas.push(Self {
                // RegexSet clones share compiled expressions but own search caches.
                groups: matcher.groups.clone(),
                index: Arc::clone(&matcher.index),
                scratch: RefCell::new(SearchScratch {
                    selected_groups: vec![0; matcher.groups.len().div_ceil(64)],
                    seen_literals: vec![0; matcher.index.literal_groups.len().div_ceil(64)],
                    literal_candidates: CandidateScratch::default(),
                }),
            });
        }
        replicas.push(matcher);
        Ok(replicas)
    }

    fn new(rules: &[Rule], plans: Vec<GroupPlan>) -> Result<Self> {
        let mut groups = Vec::with_capacity(plans.len());
        let mut prefixes = PrefixIndex::default();
        let mut fallback = vec![Vec::new(); EMPTY_INPUT_BUCKET + 1];
        let mut literal_map: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
        let mut literal_first_bytes = ByteSet::empty();
        // Divide the worker's cache target between its sets instead of giving
        // every small set the old whole-shard 128 MiB cache allowance.
        let dfa_cache_limit =
            (DFA_CACHE_BUDGET_PER_WORKER / plans.len().max(1)).min(MAX_GROUP_DFA_CACHE);

        for (group_id, plan) in plans.into_iter().enumerate() {
            let engine = if let GroupCondition::Primitive(primitive) = &plan.condition {
                GroupEngine::Primitive(*primitive)
            } else if let GroupCondition::LiteralTail(predicate) = &plan.condition {
                GroupEngine::LiteralTail {
                    predicate: predicate.clone(),
                    finder: Finder::new(&predicate.literal).into_owned(),
                }
            } else {
                let expressions = plan.rule_ids.iter().map(|&id| &rules[id].expression);
                let set = RegexSetBuilder::new(expressions)
                    .unicode(false)
                    .size_limit(SET_SIZE_LIMIT)
                    .dfa_size_limit(dfa_cache_limit)
                    .build()
                    .with_context(|| format!("could not compile regex group {group_id}"))?;
                if plan.rule_ids.len() == 1 {
                    GroupEngine::Single(set)
                } else {
                    GroupEngine::Regex(set)
                }
            };

            match plan.condition {
                GroupCondition::Prefixes(literals) => {
                    for literal in literals {
                        prefixes.insert(&literal, group_id);
                    }
                }
                GroupCondition::Literals(literals) => {
                    for literal in literals {
                        literal_map.entry(literal).or_default().push(group_id);
                    }
                    literal_first_bytes.union(plan.guard.first_bytes);
                }
                GroupCondition::LiteralTail(predicate) => {
                    literal_map
                        .entry(predicate.literal)
                        .or_default()
                        .push(group_id);
                    literal_first_bytes.union(plan.guard.first_bytes);
                }
                GroupCondition::FirstBytes(_) | GroupCondition::Primitive(_) => {
                    let first_bytes = plan.guard.first_bytes;
                    for (byte, bucket) in fallback[..EMPTY_INPUT_BUCKET].iter_mut().enumerate() {
                        if first_bytes.contains(byte as u8) {
                            bucket.push(group_id);
                        }
                    }
                    if plan.guard.minimum_len == Some(0) {
                        fallback[EMPTY_INPUT_BUCKET].push(group_id);
                    }
                }
            }
            groups.push(RegexGroup {
                engine,
                rule_ids: plan.rule_ids.into(),
                guard: plan.guard,
            });
        }

        let literal_search = if literal_map.is_empty() {
            None
        } else {
            Some(Box::new(LiteralCandidates::new(literal_map.keys())?))
        };
        let literal_groups: Vec<_> = literal_map.into_values().collect();
        let scratch = SearchScratch {
            selected_groups: vec![0; groups.len().div_ceil(64)],
            seen_literals: vec![0; literal_groups.len().div_ceil(64)],
            literal_candidates: CandidateScratch::default(),
        };
        Ok(Self {
            groups,
            index: Arc::new(GroupIndex {
                prefixes,
                fallback,
                literal_search,
                literal_groups,
                literal_first_bytes,
            }),
            scratch: RefCell::new(scratch),
        })
    }

    pub fn matching_rules(&self, bytes: &[u8]) -> Vec<usize> {
        self.matching_rules_inner::<false>(bytes, 0, &mut MatchingTime::default())
    }

    pub fn matching_rules_diagnostic(
        &self,
        bytes: &[u8],
        request_id: u64,
        timing: &mut MatchingTime,
    ) -> Vec<usize> {
        self.matching_rules_inner::<true>(bytes, request_id, timing)
    }

    pub fn group_descriptions(&self, rules: &[Rule]) -> Vec<GroupDescription> {
        self.groups
            .iter()
            .enumerate()
            .map(|(group_id, group)| GroupDescription {
                group_id,
                engine: match &group.engine {
                    GroupEngine::Regex(_) => "regex_set",
                    GroupEngine::Single(_) => "singleton_is_match",
                    GroupEngine::LiteralTail { .. } => "literal_gap_byte_class",
                    GroupEngine::Primitive(Primitive::MinLength(_)) => "minimum_byte_length",
                    GroupEngine::Primitive(Primitive::ByteAfterPrefix { .. }) => {
                        "byte_after_prefix"
                    }
                },
                minimum_len: group.guard.minimum_len,
                rules: group
                    .rule_ids
                    .iter()
                    .map(|&rule_id| RuleDescription {
                        rule_id,
                        line: rules[rule_id].line_number,
                        service: rules[rule_id].service.clone(),
                        expression: rules[rule_id].expression.clone(),
                    })
                    .collect(),
            })
            .collect()
    }

    fn matching_rules_inner<const DIAG: bool>(
        &self,
        bytes: &[u8],
        request_id: u64,
        timing: &mut MatchingTime,
    ) -> Vec<usize> {
        let filter_start = DIAG.then(Instant::now);
        let index = &self.index;
        let mut scratch = self.scratch.borrow_mut();
        scratch.selected_groups.fill(0);
        scratch.seen_literals.fill(0);

        let bucket = bytes
            .first()
            .map_or(EMPTY_INPUT_BUCKET, |&byte| byte as usize);
        for &group_id in &index.fallback[bucket] {
            mark(&mut scratch.selected_groups, group_id);
        }
        index.prefixes.select(bytes, &mut scratch.selected_groups);

        if let Some(start) = filter_start {
            timing.prefix_seconds += start.elapsed().as_secs_f64();
        }
        let literal_start = DIAG.then(Instant::now);
        let mut occurrences = 0;
        let mut distinct = 0;
        if let Some(search) = &index.literal_search {
            if bytes
                .first()
                .is_some_and(|&byte| index.literal_first_bytes.contains(byte))
            {
                let SearchScratch {
                    selected_groups,
                    seen_literals,
                    literal_candidates,
                } = &mut *scratch;
                let select_literal = |literal_id| {
                    if mark(seen_literals, literal_id) {
                        if DIAG {
                            distinct += 1;
                        }
                        for &group_id in &index.literal_groups[literal_id] {
                            mark(selected_groups, group_id);
                        }
                    }
                };
                occurrences = search.select::<DIAG>(bytes, literal_candidates, select_literal);
            }
        }

        if let Some(start) = literal_start {
            timing.literal_seconds += start.elapsed().as_secs_f64();
            timing.literal_occurrences += occurrences;
            timing.distinct_literals_per_request_sum += distinct;
        }
        if let Some(start) = filter_start {
            timing.filter_seconds += start.elapsed().as_secs_f64();
        }
        let mut matches = Vec::new();
        for (word_index, &word) in scratch.selected_groups.iter().enumerate() {
            let mut remaining = word;
            while remaining != 0 {
                let group_id = word_index * 64 + remaining.trailing_zeros() as usize;
                remaining &= remaining - 1;
                let group = &self.groups[group_id];
                if !group.guard.admits(bytes) {
                    continue;
                }
                // A routing hit selects an engine: either the original set or
                // a predicate recognizing exactly the same byte language.
                let start = DIAG.then(Instant::now);
                let before = matches.len();
                match &group.engine {
                    GroupEngine::Regex(regex) => {
                        matches.extend(regex.matches(bytes).iter().map(|id| group.rule_ids[id]));
                    }
                    GroupEngine::Single(regex) => {
                        if regex.is_match(bytes) {
                            matches.push(group.rule_ids[0]);
                        }
                    }
                    GroupEngine::Primitive(primitive) => {
                        if primitive.matches(bytes) {
                            matches.extend(group.rule_ids.iter().copied());
                        }
                    }
                    GroupEngine::LiteralTail { predicate, finder } => {
                        if predicate.matches(bytes, finder) {
                            matches.extend(group.rule_ids.iter().copied());
                        }
                    }
                }
                if let Some(start) = start {
                    let seconds = start.elapsed().as_secs_f64();
                    timing.groups[group_id].record(
                        request_id,
                        bytes.len(),
                        seconds,
                        matches.len() - before,
                    );
                }
            }
        }
        // Every rule belongs to one group, and each selected group runs once.
        matches.sort_unstable();
        matches
    }
}

fn plan_groups(rules: &[Rule]) -> Result<Vec<GroupPlan>> {
    let mut buckets: BTreeMap<GroupCondition, Vec<(usize, RuleGuard)>> = BTreeMap::new();
    for (rule_id, rule) in rules.iter().enumerate() {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(&rule.expression)
            .with_context(|| format!("could not analyze rule at line {}", rule.line_number))?;
        let anchored = hir.properties().look_set_prefix().contains(Look::Start);
        let guard = RuleGuard::new(&hir, anchored);
        if guard.minimum_len.is_none() {
            continue;
        }

        let prefix = if anchored {
            extract_literals(&hir, ExtractKind::Prefix)
        } else {
            None
        };
        let primitive = Primitive::from_hir(&hir);
        let literal_tail = LiteralTail::from_hir(&hir);
        let condition = if let Some(primitive) = primitive {
            GroupCondition::Primitive(primitive)
        } else if let Some(predicate) = literal_tail {
            GroupCondition::LiteralTail(predicate)
        } else if let Some(mut literals) = prefix {
            // A shared short prefix forms useful groups even when full extracted
            // prefixes differ. Truncation weakens the filter but cannot lose hits.
            for literal in &mut literals {
                literal.truncate(GROUP_PREFIX_BYTES);
            }
            literals.sort_unstable();
            literals.dedup();
            GroupCondition::Prefixes(literals)
        } else if let Some(literals) = selective_literals(&hir) {
            GroupCondition::Literals(literals)
        } else {
            // Unanchored/nullable rules get conservative first-byte sets. Never
            // infer an HTTP method or discard a rule merely from its service name.
            GroupCondition::FirstBytes(guard.first_bytes)
        };
        buckets.entry(condition).or_default().push((rule_id, guard));
    }

    let mut plans = Vec::new();
    for (condition, members) in buckets {
        for chunk in members.chunks(MAX_GROUP_RULES) {
            let mut minimum_len = usize::MAX;
            let mut first_bytes = ByteSet::empty();
            let mut rule_ids = Vec::with_capacity(chunk.len());
            for &(rule_id, guard) in chunk {
                minimum_len = minimum_len.min(guard.minimum_len.expect("empty languages excluded"));
                first_bytes.union(guard.first_bytes);
                rule_ids.push(rule_id);
            }
            plans.push(GroupPlan {
                condition: condition.clone(),
                rule_ids,
                // A group can be skipped only if none of its rules can match.
                guard: RuleGuard {
                    minimum_len: Some(minimum_len),
                    first_bytes,
                },
            });
        }
    }
    Ok(plans)
}
