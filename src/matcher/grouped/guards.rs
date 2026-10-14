//! Conservative length, first-byte and prefix conditions for rule groups.

use regex_syntax::hir::literal::{ExtractKind, Extractor};
use regex_syntax::hir::{Class, Hir, HirKind};

const MAX_LITERALS: usize = 64;
const MAX_LITERAL_BYTES: usize = 16;

pub(super) fn mark(words: &mut [u64], index: usize) -> bool {
    let word = &mut words[index / 64];
    let bit = 1u64 << (index % 64);
    let was_missing = *word & bit == 0;
    *word |= bit;
    was_missing
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ByteSet([u64; 4]);

impl ByteSet {
    pub(super) fn empty() -> Self {
        Self([0; 4])
    }

    fn all() -> Self {
        Self([u64::MAX; 4])
    }

    pub(super) fn insert(&mut self, byte: u8) {
        self.0[byte as usize / 64] |= 1u64 << (byte % 64);
    }

    pub(super) fn contains(self, byte: u8) -> bool {
        self.0[byte as usize / 64] & (1u64 << (byte % 64)) != 0
    }

    pub(super) fn union(&mut self, other: Self) {
        for (word, other_word) in self.0.iter_mut().zip(other.0) {
            *word |= other_word;
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct RuleGuard {
    pub(super) minimum_len: Option<usize>,
    pub(super) first_bytes: ByteSet,
}

impl RuleGuard {
    pub(super) fn new(hir: &Hir, anchored: bool) -> Self {
        let minimum_len = hir.properties().minimum_len();
        let mut first_bytes = ByteSet::all();
        if anchored && minimum_len.is_some_and(|length| length > 0) {
            first_bytes = ByteSet::empty();
            collect_first_bytes(hir, &mut first_bytes);
        }
        Self {
            minimum_len,
            first_bytes,
        }
    }

    pub(super) fn admits(self, bytes: &[u8]) -> bool {
        self.minimum_len.is_some_and(|length| bytes.len() >= length)
            && bytes
                .first()
                .is_none_or(|&byte| self.first_bytes.contains(byte))
    }
}

fn collect_first_bytes(hir: &Hir, allowed: &mut ByteSet) {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => {}
        HirKind::Literal(literal) => {
            if let Some(&byte) = literal.0.first() {
                allowed.insert(byte);
            }
        }
        HirKind::Class(Class::Bytes(class)) => {
            for range in class.iter() {
                for byte in range.start()..=range.end() {
                    allowed.insert(byte);
                }
            }
        }
        // Unicode classes may consume several UTF-8 bytes. Keep a conservative set.
        HirKind::Class(Class::Unicode(_)) => *allowed = ByteSet::all(),
        HirKind::Capture(capture) => collect_first_bytes(&capture.sub, allowed),
        HirKind::Repetition(repetition) => collect_first_bytes(&repetition.sub, allowed),
        HirKind::Alternation(branches) => {
            for branch in branches {
                collect_first_bytes(branch, allowed);
            }
        }
        HirKind::Concat(parts) => {
            for part in parts {
                collect_first_bytes(part, allowed);
                if part.properties().minimum_len() != Some(0) {
                    break;
                }
            }
        }
    }
}

pub(super) fn extract_literals(hir: &Hir, kind: ExtractKind) -> Option<Vec<Vec<u8>>> {
    let sequence = Extractor::new()
        .kind(kind)
        .limit_literal_len(MAX_LITERAL_BYTES)
        .limit_total(MAX_LITERALS)
        .extract(hir);
    let literals = sequence.literals()?;
    if literals.is_empty() || literals.iter().any(|literal| literal.as_bytes().is_empty()) {
        return None;
    }
    Some(compact_literals(
        literals
            .iter()
            .map(|literal| literal.as_bytes().to_vec())
            .collect(),
    ))
}

fn compact_literals(mut literals: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    literals.sort_unstable();
    let mut compact: Vec<Vec<u8>> = Vec::with_capacity(literals.len());
    for literal in literals {
        // A shorter prefix covers this alternative too, including equal literals.
        if !compact
            .last()
            .is_some_and(|prefix| literal.starts_with(prefix))
        {
            compact.push(literal);
        }
    }
    compact
}

pub(super) struct PrefixIndex {
    roots: [Option<usize>; 256],
    nodes: Vec<PrefixNode>,
}

impl Default for PrefixIndex {
    fn default() -> Self {
        Self {
            roots: [None; 256],
            nodes: Vec::new(),
        }
    }
}

#[derive(Default)]
struct PrefixNode {
    children: Vec<(u8, usize)>,
    rules: Vec<usize>,
}

impl PrefixIndex {
    pub(super) fn insert(&mut self, prefix: &[u8], rule_id: usize) {
        let first = prefix[0] as usize;
        let mut node_id = match self.roots[first] {
            Some(node_id) => node_id,
            None => {
                let node_id = self.nodes.len();
                self.nodes.push(PrefixNode::default());
                self.roots[first] = Some(node_id);
                node_id
            }
        };
        for &byte in &prefix[1..] {
            node_id = match self.nodes[node_id]
                .children
                .binary_search_by_key(&byte, |&(key, _)| key)
            {
                Ok(position) => self.nodes[node_id].children[position].1,
                Err(position) => {
                    let child_id = self.nodes.len();
                    self.nodes.push(PrefixNode::default());
                    self.nodes[node_id]
                        .children
                        .insert(position, (byte, child_id));
                    child_id
                }
            };
        }
        self.nodes[node_id].rules.push(rule_id);
    }

    pub(super) fn select(&self, bytes: &[u8], candidates: &mut [u64]) {
        let Some((&first, remaining)) = bytes.split_first() else {
            return;
        };
        let Some(mut node_id) = self.roots[first as usize] else {
            return;
        };
        let mut remaining = remaining.iter();
        loop {
            let node = &self.nodes[node_id];
            for &rule_id in &node.rules {
                mark(candidates, rule_id);
            }
            let Some(&byte) = remaining.next() else {
                break;
            };
            let Ok(position) = node.children.binary_search_by_key(&byte, |&(key, _)| key) else {
                break;
            };
            node_id = node.children[position].1;
        }
    }
}
