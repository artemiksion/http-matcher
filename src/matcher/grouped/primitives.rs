//! Exact byte predicates and necessary literals derived from regex structure.

use aho_corasick::automaton::Automaton;
use aho_corasick::{dfa::DFA, Anchored};
use anyhow::{Context, Result};
use memchr::memmem::Finder;
use regex_syntax::hir::literal::ExtractKind;
use regex_syntax::hir::{Class, Hir, HirKind, Look};

use super::guards::{extract_literals, ByteSet};

const MAX_ATOM_BYTES: usize = 16;
const MAX_ALTERNATIVES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Primitive {
    MinLength(usize),
    ByteAfterPrefix { offset: usize, byte: u8 },
}

impl Primitive {
    pub(super) fn matches(self, bytes: &[u8]) -> bool {
        match self {
            Self::MinLength(length) => bytes.len() >= length,
            Self::ByteAfterPrefix { offset, byte } => {
                bytes.get(offset..).is_some_and(|tail| tail.contains(&byte))
            }
        }
    }

    // Recognize only exact byte-language equivalents. Captures do not affect
    // boolean matching; Unicode dots, line anchors and end assertions do.
    pub(super) fn from_hir(hir: &Hir) -> Option<Self> {
        let mut parts = Vec::new();
        flatten(hir, &mut parts);
        if !matches!(parts.first()?.kind(), HirKind::Look(Look::Start)) {
            return None;
        }
        let parts = &parts[1..];
        let minimum = parts
            .iter()
            .try_fold(0usize, |total, part| total.checked_add(any_minimum(part)?));
        if let Some(minimum) = minimum {
            return Some(Self::MinLength(minimum));
        }
        let (last, prefix) = parts.split_last()?;
        let HirKind::Literal(literal) = last.kind() else {
            return None;
        };
        if literal.0.len() != 1 {
            return None;
        }
        let (tail, prefix) = prefix.split_last()?;
        let HirKind::Repetition(repetition) = tail.kind() else {
            return None;
        };
        if repetition.max.is_some() || any_fixed(&repetition.sub) != Some(1) {
            return None;
        }
        let offset = prefix
            .iter()
            .try_fold(repetition.min as usize, |total, part| {
                total.checked_add(any_fixed(part)?)
            })?;
        Some(Self::ByteAfterPrefix {
            offset,
            byte: literal.0[0],
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct LiteralTail {
    pub(super) literal: Vec<u8>,
    gap: usize,
    allowed: ByteSet,
}

impl LiteralTail {
    // Exact shape: absolute start, arbitrary byte prefix, fixed literal,
    // a fixed number of arbitrary bytes, then one-or-more class bytes.
    // No suffix/end assertion or other constraint may be discarded.
    pub(super) fn from_hir(hir: &Hir) -> Option<Self> {
        let mut parts = Vec::new();
        flatten(hir, &mut parts);
        if parts.len() < 4 || !matches!(parts[0].kind(), HirKind::Look(Look::Start)) {
            return None;
        }
        let HirKind::Repetition(prefix) = parts[1].kind() else {
            return None;
        };
        if prefix.min != 0 || prefix.max.is_some() || any_fixed(&prefix.sub) != Some(1) {
            return None;
        }
        let HirKind::Literal(literal) = parts[2].kind() else {
            return None;
        };
        if literal.0.is_empty() {
            return None;
        }
        let HirKind::Repetition(tail) = parts.last()?.kind() else {
            return None;
        };
        if tail.min != 1 || tail.max.is_some() {
            return None;
        }
        let gap = parts[3..parts.len() - 1]
            .iter()
            .try_fold(0usize, |total, part| total.checked_add(any_fixed(part)?))?;
        let mut allowed = ByteSet::empty();
        match tail.sub.kind() {
            HirKind::Class(Class::Bytes(class)) => {
                for range in class.iter() {
                    for byte in range.start()..=range.end() {
                        allowed.insert(byte);
                    }
                }
            }
            HirKind::Literal(literal) if literal.0.len() == 1 => allowed.insert(literal.0[0]),
            _ => return None,
        }
        Some(Self {
            literal: literal.0.to_vec(),
            gap,
            allowed,
        })
    }

    pub(super) fn matches(&self, bytes: &[u8], finder: &Finder<'_>) -> bool {
        let mut start = 0;
        while let Some(relative) = finder.find(&bytes[start..]) {
            let offset = start + relative;
            if offset
                .checked_add(self.literal.len())
                .and_then(|end| end.checked_add(self.gap))
                .and_then(|index| bytes.get(index))
                .is_some_and(|&byte| self.allowed.contains(byte))
            {
                return true;
            }
            // Covers overlapping occurrences too, even when the literal has a
            // repeated prefix/suffix and the first candidate fails its tail.
            start = offset + 1;
        }
        false
    }
}

fn flatten<'a>(hir: &'a Hir, parts: &mut Vec<&'a Hir>) {
    match hir.kind() {
        HirKind::Capture(capture) => flatten(&capture.sub, parts),
        HirKind::Concat(children) => {
            for child in children {
                flatten(child, parts);
            }
        }
        HirKind::Empty => {}
        _ => parts.push(hir),
    }
}

fn any_minimum(hir: &Hir) -> Option<usize> {
    match hir.kind() {
        HirKind::Empty => Some(0),
        HirKind::Class(Class::Bytes(class)) if class.iter().count() == 1 => {
            let range = class.iter().next()?;
            (range.start() == 0 && range.end() == 255).then_some(1)
        }
        HirKind::Capture(capture) => any_minimum(&capture.sub),
        HirKind::Concat(parts) => parts
            .iter()
            .try_fold(0usize, |total, part| total.checked_add(any_minimum(part)?)),
        HirKind::Repetition(repetition) => {
            any_minimum(&repetition.sub)?.checked_mul(repetition.min as usize)
        }
        _ => None,
    }
}

fn any_fixed(hir: &Hir) -> Option<usize> {
    match hir.kind() {
        HirKind::Repetition(repetition) if repetition.max != Some(repetition.min) => None,
        HirKind::Repetition(repetition) => {
            any_fixed(&repetition.sub)?.checked_mul(repetition.min as usize)
        }
        HirKind::Capture(capture) => any_fixed(&capture.sub),
        HirKind::Concat(parts) => parts
            .iter()
            .try_fold(0usize, |total, part| total.checked_add(any_fixed(part)?)),
        _ => any_minimum(hir),
    }
}

// A cover is ORed: every possible match contains at least one returned atom.
// Scoring changes only which necessary condition is used, never its coverage.
pub(super) fn selective_literals(hir: &Hir) -> Option<Vec<Vec<u8>>> {
    let mut best = None;
    choose(&mut best, extract_literals(hir, ExtractKind::Prefix));
    choose(&mut best, extract_literals(hir, ExtractKind::Suffix));
    match hir.kind() {
        HirKind::Literal(literal) => {
            choose(&mut best, Some(vec![best_window(&literal.0).to_vec()]));
        }
        HirKind::Concat(parts) => {
            for part in parts {
                choose(&mut best, selective_literals(part));
            }
        }
        HirKind::Capture(capture) => choose(&mut best, selective_literals(&capture.sub)),
        HirKind::Repetition(repetition) if repetition.min > 0 => {
            choose(&mut best, selective_literals(&repetition.sub));
        }
        HirKind::Alternation(branches) => {
            let mut cover = Vec::new();
            for branch in branches {
                let Some(atoms) = selective_literals(branch) else {
                    return best;
                };
                cover.extend(atoms);
                cover.sort_unstable();
                cover.dedup();
                if cover.len() > MAX_ALTERNATIVES {
                    return best;
                }
            }
            choose(&mut best, Some(cover));
        }
        _ => {}
    }
    best
}

fn best_window(bytes: &[u8]) -> &[u8] {
    if bytes.len() <= MAX_ATOM_BYTES {
        return bytes;
    }
    bytes
        .windows(MAX_ATOM_BYTES)
        .max_by_key(|window| quality(window))
        .unwrap()
}

fn quality(bytes: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut distinct = 0;
    let mut informative = 0;
    for &byte in bytes {
        if !seen[byte as usize] {
            distinct += 1;
            seen[byte as usize] = true;
        }
        // Repeated NUL/padding is common in this corpus. Diversity takes
        // precedence over length; non-padding bytes break otherwise equal ties.
        informative += usize::from(byte != 0 && byte != b' ' && byte != 255);
    }
    distinct * 32 + informative * 2 + bytes.len()
}

fn choose(best: &mut Option<Vec<Vec<u8>>>, candidate: Option<Vec<Vec<u8>>>) {
    let Some(mut candidate) = candidate else {
        return;
    };
    if candidate.is_empty() || candidate.iter().any(|atom| atom.len() < 2) {
        return;
    }
    candidate.sort_unstable();
    candidate.dedup();
    let score = |atoms: &[Vec<u8>]| {
        (
            atoms.iter().map(|atom| quality(atom)).min().unwrap_or(0),
            std::cmp::Reverse(atoms.len()),
        )
    };
    if best
        .as_ref()
        .is_none_or(|current| score(&candidate) > score(current))
    {
        *best = Some(candidate);
    }
}

pub(super) struct LiteralDfa {
    dfa: DFA,
}

#[derive(Default)]
pub(super) struct LiteralScratch {
    epoch: u32,
    seen_states: Vec<u32>,
}

impl LiteralDfa {
    pub(super) fn new<'a>(patterns: impl Iterator<Item = &'a Vec<u8>>) -> Result<Self> {
        Ok(Self {
            dfa: DFA::builder()
                .build(patterns)
                .context("build literal presence DFA")?,
        })
    }

    pub(super) fn select<const DIAG: bool>(
        &self,
        bytes: &[u8],
        scratch: &mut LiteralScratch,
        mut on_literal: impl FnMut(usize),
    ) -> u64 {
        scratch.epoch = scratch.epoch.wrapping_add(1);
        if scratch.epoch == 0 {
            scratch.seen_states.fill(0);
            scratch.epoch = 1;
        }
        let mut state = self.dfa.start_state(Anchored::No).expect("unanchored DFA");
        let mut occurrences = 0;
        for &byte in bytes {
            state = self.dfa.next_state(Anchored::No, state, byte);
            if !self.dfa.is_match(state) {
                continue;
            }
            if DIAG {
                occurrences += self.dfa.match_len(state) as u64;
            }
            let index = state.as_usize();
            if index >= scratch.seen_states.len() {
                scratch.seen_states.resize(index + 1, 0);
            }
            if scratch.seen_states[index] == scratch.epoch {
                continue;
            }
            scratch.seen_states[index] = scratch.epoch;
            // A state always reports the same IDs, including suffix overlaps.
            // Presence needs each state's outputs once, regardless of position.
            for i in 0..self.dfa.match_len(state) {
                on_literal(self.dfa.match_pattern(state, i).as_usize());
            }
        }
        occurrences
    }
}
