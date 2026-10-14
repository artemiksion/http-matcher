//! Shared literal search with direct DFA transitions and per-worker scratch.

use std::collections::{hash_map::Entry, HashMap};

use aho_corasick::automaton::Automaton;
use aho_corasick::{dfa::DFA, Anchored};
use anyhow::{ensure, Context, Result};

use super::primitives::{LiteralDfa, LiteralScratch};

const MATCH_BIT: u32 = 1;
// A matched state's row starts one entry later, so its low bit reports a
// match and the complete state remains a valid transition offset. No mask
// is needed on the next table lookup. Even row strides preserve the flag.
const ROW_WIDTH: usize = 256 + 2;
// Shared by all workers. Large dictionaries keep the original byte-class DFA
// instead of expanding its alphabet without a memory bound.
const MAX_TABLE_BYTES: usize = 128 * 1024 * 1024;
const MAX_STATES: usize = MAX_TABLE_BYTES / (ROW_WIDTH * std::mem::size_of::<u32>());

pub(super) enum LiteralCandidates {
    Direct(DirectDfa),
    Standard(Box<LiteralDfa>),
}

pub(super) struct DirectDfa {
    transitions: Vec<u32>,
    outputs: Vec<Vec<usize>>,
    overlap: usize,
}

#[derive(Default)]
pub(super) struct CandidateScratch {
    epoch: u32,
    seen_states: Vec<u32>,
    standard: LiteralScratch,
}

impl LiteralCandidates {
    pub(super) fn new<'a>(atoms: impl Iterator<Item = &'a Vec<u8>>) -> Result<Self> {
        let atoms: Vec<_> = atoms.collect();
        Self::with_state_limit(atoms, MAX_STATES)
    }

    fn with_state_limit(atoms: Vec<&Vec<u8>>, max_states: usize) -> Result<Self> {
        ensure!(
            atoms.iter().all(|atom| !atom.is_empty()),
            "empty routing literal"
        );
        let dfa = DFA::builder()
            .build(&atoms)
            .context("build direct literal DFA")?;
        let overlap = atoms.iter().map(|atom| atom.len()).max().unwrap_or(1) - 1;
        let start = dfa.start_state(Anchored::No).context("unanchored DFA")?;
        let mut states = vec![start];
        let mut rows = HashMap::from([(start.as_usize(), 0u32)]);
        let mut transitions = Vec::new();
        let mut outputs = Vec::new();
        let mut index = 0;
        while index < states.len() {
            let state = states[index];
            let matched = dfa.is_match(state);
            outputs.push(if dfa.is_match(state) {
                (0..dfa.match_len(state))
                    .map(|i| dfa.match_pattern(state, i).as_usize())
                    .collect()
            } else {
                Vec::new()
            });
            if matched {
                transitions.push(0);
            }
            for byte in 0..=u8::MAX {
                let next = dfa.next_state(Anchored::No, state, byte);
                let row = match rows.entry(next.as_usize()) {
                    Entry::Occupied(entry) => *entry.get(),
                    Entry::Vacant(entry) => {
                        if states.len() >= max_states {
                            return Ok(Self::Standard(Box::new(LiteralDfa::new(
                                atoms.into_iter(),
                            )?)));
                        }
                        let row = (states.len() * ROW_WIDTH) as u32;
                        entry.insert(row);
                        states.push(next);
                        row
                    }
                };
                // Match rows have an unused leading entry: the flagged offset
                // directly addresses that row's first actual transition.
                transitions.push(row | if dfa.is_match(next) { MATCH_BIT } else { 0 });
            }
            transitions.resize(
                transitions.len() + ROW_WIDTH - 256 - usize::from(matched),
                0,
            );
            index += 1;
        }
        Ok(Self::Direct(DirectDfa {
            transitions,
            outputs,
            overlap,
        }))
    }

    pub(super) fn select<const DIAG: bool>(
        &self,
        bytes: &[u8],
        scratch: &mut CandidateScratch,
        mut on_literal: impl FnMut(usize),
    ) -> u64 {
        let dfa = match self {
            Self::Direct(dfa) => dfa,
            Self::Standard(dfa) => {
                return dfa.select::<DIAG>(bytes, &mut scratch.standard, on_literal);
            }
        };
        scratch.seen_states.resize(dfa.outputs.len(), 0);
        scratch.epoch = scratch.epoch.wrapping_add(1);
        if scratch.epoch == 0 {
            scratch.seen_states.fill(0);
            scratch.epoch = 1;
        }
        let mut occurrences = 0;
        if bytes.len() >= 4096.max(dfa.overlap.saturating_mul(16)) {
            let width = bytes.len() / 4;
            let (a, remaining) = bytes.split_at(width);
            let (b, remaining) = remaining.split_at(width);
            let (c, d) = remaining.split_at(width);
            let mut states = [0u32; 4];
            // The last max_literal_length - 1 bytes are enough to preserve
            // every match ending in a chunk. Context hits are not counted:
            // each occurrence belongs to the chunk containing its last byte.
            for (lane, state) in states.iter_mut().enumerate().skip(1) {
                let start = lane * width;
                for &byte in &bytes[start.saturating_sub(dfa.overlap)..start] {
                    *state = dfa.next(*state, byte);
                }
            }
            // Four independent dependency chains let the CPU overlap table
            // loads. Short inputs use the scalar loop and need no priming.
            for (((&a, &b), &c), &d) in a.iter().zip(b).zip(c).zip(&d[..width]) {
                states[0] = dfa.next(states[0], a);
                states[1] = dfa.next(states[1], b);
                states[2] = dfa.next(states[2], c);
                states[3] = dfa.next(states[3], d);
                if (states[0] | states[1] | states[2] | states[3]) & MATCH_BIT != 0 {
                    for &state in &states {
                        dfa.report::<DIAG>(state, scratch, &mut occurrences, &mut on_literal);
                    }
                }
            }
            for &byte in &d[width..] {
                states[3] = dfa.next(states[3], byte);
                dfa.report::<DIAG>(states[3], scratch, &mut occurrences, &mut on_literal);
            }
        } else {
            let mut state = 0u32;
            for &byte in bytes {
                state = dfa.next(state, byte);
                dfa.report::<DIAG>(state, scratch, &mut occurrences, &mut on_literal);
            }
        }
        occurrences
    }
}

impl DirectDfa {
    #[inline(always)]
    fn next(&self, state: u32, byte: u8) -> u32 {
        self.transitions[state as usize + usize::from(byte)]
    }

    #[inline(always)]
    fn report<const DIAG: bool>(
        &self,
        state: u32,
        scratch: &mut CandidateScratch,
        occurrences: &mut u64,
        on_literal: &mut impl FnMut(usize),
    ) {
        if state & MATCH_BIT == 0 {
            return;
        }
        let index = state as usize / ROW_WIDTH;
        let outputs = &self.outputs[index];
        if DIAG {
            *occurrences += outputs.len() as u64;
        }
        if scratch.seen_states[index] == scratch.epoch {
            return;
        }
        scratch.seen_states[index] = scratch.epoch;
        // Preserve suffix/overlap outputs. Presence needs each state's
        // outputs once; diagnostics count every occurrence.
        for &id in outputs {
            on_literal(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aho_corasick::AhoCorasick;
    use std::collections::BTreeSet;

    #[test]
    fn memory_limit_falls_back_without_losing_overlapping_or_binary_literals() {
        let atoms = vec![b"aa".to_vec(), b"a".to_vec(), b"\0\xff".to_vec()];
        let search = LiteralCandidates::with_state_limit(atoms.iter().collect(), 1).unwrap();
        assert!(matches!(search, LiteralCandidates::Standard(_)));
        let oracle = AhoCorasick::new(&atoms).unwrap();
        let bytes = b"aaa\0\xffaaa";
        let mut scratch = CandidateScratch::default();
        let mut actual = BTreeSet::new();
        let count = search.select::<true>(bytes, &mut scratch, |id| {
            actual.insert(id);
        });
        let expected: BTreeSet<_> = oracle
            .find_overlapping_iter(bytes)
            .map(|found| found.pattern().as_usize())
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(count, oracle.find_overlapping_iter(bytes).count() as u64);
    }

    #[test]
    fn direct_transitions_preserve_partial_code_points_and_binary_matches() {
        let atoms: Vec<Vec<u8>> = [
            b"alpha".as_slice(),
            b"\x80",
            b"\xc3",
            b"\xc3\xa9",
            b"\xa9 ",
            b"\x80\x80\x80",
            b"\x80\x80\x80\x80",
            b"\0\x80",
            b"\xff",
            b"\xe0\x9f",
            b"\xf4\x8f\xbf",
            b"\0",
            b"\xed\xa0",
            b"\xf5",
        ]
        .iter()
        .map(|atom| atom.to_vec())
        .collect();
        let search = LiteralCandidates::new(atoms.iter()).unwrap();
        let oracle = AhoCorasick::new(&atoms).unwrap();
        let mut scratch = CandidateScratch::default();
        let mut inputs = vec![
            Vec::new(),
            b"alpha\0alpha".to_vec(),
            "alpha café ☃ \u{10000} \u{10ffff}".as_bytes().to_vec(),
            b"\xff\0\x80\xe0\x9f\xed\xa0\xf5\x80\x80\x80\x80".to_vec(),
        ];
        let points = [
            '\0',
            'a',
            '\u{80}',
            '\u{7ff}',
            '\u{d7ff}',
            '\u{ffff}',
            '\u{10000}',
            '\u{10ffff}',
        ];
        for &a in &points {
            for &b in &points {
                inputs.push(format!("alpha{a}{b} alpha{b}{a} ").into_bytes());
            }
        }
        for bytes in inputs {
            let expected: BTreeSet<_> = oracle
                .find_overlapping_iter(&bytes)
                .map(|found| found.pattern().as_usize())
                .collect();
            for diagnostic in [false, true] {
                let mut actual = BTreeSet::new();
                let count = if diagnostic {
                    search.select::<true>(&bytes, &mut scratch, |id| {
                        actual.insert(id);
                    })
                } else {
                    search.select::<false>(&bytes, &mut scratch, |id| {
                        actual.insert(id);
                    })
                };
                assert_eq!(actual, expected);
                assert_eq!(
                    count,
                    if diagnostic {
                        oracle.find_overlapping_iter(&bytes).count() as u64
                    } else {
                        0
                    }
                );
            }
        }
        scratch.epoch = u32::MAX;
        let mut actual = BTreeSet::new();
        search.select::<false>(b"alpha\0alpha", &mut scratch, |id| {
            actual.insert(id);
        });
        let expected: BTreeSet<_> = oracle
            .find_overlapping_iter(b"alpha\0alpha")
            .map(|found| found.pattern().as_usize())
            .collect();
        assert_eq!(actual, expected);
    }
}
