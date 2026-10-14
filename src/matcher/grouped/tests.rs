use super::primitives::{LiteralDfa, LiteralScratch};
use super::*;
use crate::input::MatchKind;
use aho_corasick::AhoCorasick;
use regex::bytes::Regex;
use std::collections::BTreeSet;

fn hir(expression: &str) -> regex_syntax::hir::Hir {
    ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .build()
        .parse(expression)
        .unwrap()
}

#[test]
fn primitives_preserve_binary_dot_flags_anchors_and_boundaries() {
    let recognized = [
        "(?s-u:^.........(.*)\\x00)",
        "(?s-u:^.{111})",
        "(?s-u:^.{3,7}(?:..){2,3})",
        "(?s-u:^..(?:.*?)A)",
        "(?s-u:^.{3}.+\\x00)",
    ];
    let mut inputs = vec![
        Vec::new(),
        vec![0; 9],
        vec![0; 10],
        vec![255; 110],
        vec![255; 111],
    ];
    for length in 0usize..=130 {
        for position in [0, 8, 9, 10, length.saturating_sub(1)] {
            let mut input = vec![b'\n'; length];
            if position < length {
                input[position] = 0;
            }
            inputs.push(input);
        }
        inputs.push(vec![b'A'; length]);
    }
    for expression in recognized {
        let primitive = Primitive::from_hir(&hir(expression)).unwrap();
        let regex = Regex::new(expression).unwrap();
        for input in &inputs {
            assert_eq!(
                primitive.matches(input),
                regex.is_match(input),
                "{expression}, len={}",
                input.len()
            );
        }
    }
    for expression in [
        "(?-u:^.........(.*)\\x00)",
        "(?su:^.{111})",
        "(?ms-u:^.{111})",
        "(?s-u:^.{111}$)",
        "(?s-u:^.{3}[a-z])",
        "(?s-u:^.{3}.{0,5}\\x00)",
        "(?s-u:^.{3}(?:..)*\\x00)",
        "(?s-u:.{111})",
    ] {
        assert!(
            Primitive::from_hir(&hir(expression)).is_none(),
            "{expression}"
        );
    }
}

#[test]
fn literal_presence_reports_all_overlaps_once_per_state_across_requests() {
    let atoms: Vec<Vec<u8>> = [
        b"he".as_slice(),
        b"she",
        b"hers",
        b"aa",
        b"aaa",
        b"aab",
        b"\0\0",
    ]
    .iter()
    .map(|bytes| bytes.to_vec())
    .collect();
    let presence = LiteralDfa::new(atoms.iter()).unwrap();
    let occurrences = AhoCorasick::new(&atoms).unwrap();
    let mut scratch = LiteralScratch::default();
    for input in [
        b"shehersaaaaaab\0\0\0".as_slice(),
        b"",
        b"aaaaaa",
        b"hers",
        b"no hits",
        b"shehersaaaaaab\0\0\0",
    ] {
        let expected: BTreeSet<_> = occurrences
            .find_overlapping_iter(input)
            .map(|found| found.pattern().as_usize())
            .collect();
        let mut actual = BTreeSet::new();
        let count = presence.select::<true>(input, &mut scratch, |id| {
            actual.insert(id);
        });
        assert_eq!(actual, expected);
        assert_eq!(
            count,
            occurrences.find_overlapping_iter(input).count() as u64
        );
    }
}

#[test]
fn literal_candidates_preserve_block_edges_suffix_binary_matches_and_occurrence_counts() {
    let atoms: Vec<Vec<u8>> = [
        b"abcdef0123456789".as_slice(),
        b"abc",
        b"bc",
        b"aa",
        b"aaa",
        b"\0\xff\0",
        b"abc",
        b"ababac",
    ]
    .iter()
    .map(|bytes| bytes.to_vec())
    .collect();
    let presence = LiteralCandidates::new(atoms.iter()).unwrap();
    let occurrences = AhoCorasick::new(&atoms).unwrap();
    let mut scratch = CandidateScratch::default();
    let mut cases = Vec::new();
    for length in [
        0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 511, 512, 513, 514, 515, 1024, 2049, 4095, 4096, 4097,
        4098, 4099, 8191, 8192, 8193,
    ] {
        cases.push(vec![b'a'; length]);
        let mut input = vec![b'_'; length];
        for boundary in [
            8,
            16,
            24,
            length / 4,
            length / 4 * 2,
            length / 4 * 3,
            length,
        ] {
            for atom in &atoms {
                for prefix in 0..=atom.len() {
                    let Some(start) = boundary.checked_sub(prefix) else {
                        continue;
                    };
                    if start + atom.len() <= input.len() {
                        input[start..start + atom.len()].copy_from_slice(atom);
                        cases.push(input.clone());
                        input[start..start + atom.len()].fill(b'_');
                    }
                }
            }
        }
    }
    cases.push(b"ababababac abc abc bc abcdef0123456789".to_vec());
    // Exercise general binary contexts and the final partial block too.
    let mut seed = 0x1234_5678u32;
    for _ in 0..128 {
        let mut input = vec![0; 8195];
        for byte in &mut input {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *byte = [0, 255, b'a', b'b', b'c', b'x', b'_'][seed as usize % 7];
        }
        cases.push(input);
    }
    for input in cases {
        let expected: BTreeSet<_> = occurrences
            .find_overlapping_iter(&input)
            .map(|found| found.pattern().as_usize())
            .collect();
        let mut actual = BTreeSet::new();
        let count = presence.select::<true>(&input, &mut scratch, |id| {
            actual.insert(id);
        });
        assert_eq!(actual, expected, "input len {}", input.len());
        assert_eq!(
            count,
            occurrences.find_overlapping_iter(&input).count() as u64
        );
        let mut ordinary = BTreeSet::new();
        assert_eq!(
            presence.select::<false>(&input, &mut scratch, |id| {
                ordinary.insert(id);
            }),
            0
        );
        assert_eq!(ordinary, expected);
    }
    // Single-byte keys and empty input must keep their exact byte semantics.
    let short = [b"x".to_vec(), b"abc".to_vec()];
    let fallback = LiteralCandidates::new(short.iter()).unwrap();
    let mut actual = BTreeSet::new();
    assert_eq!(
        fallback.select::<true>(b"xabcx", &mut scratch, |id| {
            actual.insert(id);
        }),
        3
    );
    assert_eq!(actual, BTreeSet::from([0, 1]));
    assert!(LiteralCandidates::new([Vec::new()].iter()).is_err());
    let empty = LiteralCandidates::new(std::iter::empty()).unwrap();
    assert_eq!(
        empty.select::<true>(b"anything", &mut scratch, |_| panic!(
            "empty filter matched"
        )),
        0
    );
}

#[test]
fn selective_atoms_replace_padding_without_losing_alternation_coverage() {
    let expression = "(?s-u:^.*Donkey\\x01\\x0c\\x00\\./donkey\\.ini\\x00{21})";
    let atoms = selective_literals(&hir(expression)).unwrap();
    assert!(atoms.iter().all(|atom| atom.iter().any(|&byte| byte != 0)));
    let expression = "(?s-u:(?:.*alpha.{2}|.*beta.{3}))";
    let atoms = selective_literals(&hir(expression)).unwrap();
    let search = AhoCorasick::new(atoms).unwrap();
    let regex = Regex::new(expression).unwrap();
    for input in [b"alpha12".as_slice(), b"beta123", b"xalpha\n\0", b"nothing"] {
        assert!(!regex.is_match(input) || search.is_match(input));
    }
    assert!(selective_literals(&hir("(?s-u:(?:token.*|.*))")).is_none());
}

#[test]
fn fast_groups_preserve_all_rule_ids_and_duplicate_primitives() {
    let expressions = [
        "(?s-u:^.........(.*)\\x00)",
        "(?s-u:^.........(.*)\\x00)",
        "(?s-u:^.{111})",
        "(?s-u:^.{128}[\\x52-\\x7F]...$)",
        "(?s-u:^.[\\x40\\xc0].[\\x20\\x23])",
        "(?s-u:^.*Donkey.{2}\\./donkey\\.ini\\x00{21})",
        "(?-u:\\x1bY2\\x00.{20}\\x00{21})",
        "(?s-u:^.*version.....([\\.\\d]+))",
        "(?s-u:.*(?:alpha..|beta...))",
        "(?-u:aa|aaa|aab)",
        "(?-u:^a?b)",
        "(?-u:a*)",
        "(?i-u:abc)",
        "(?-u:^GET )",
    ];
    let rules: Vec<_> = expressions
        .iter()
        .enumerate()
        .map(|(id, expression)| Rule {
            service: format!("rule{id}"),
            kind: MatchKind::Match,
            probe_order: 0,
            line_number: id + 1,
            expression: expression.to_string(),
        })
        .collect();
    let regexes: Vec<_> = expressions
        .iter()
        .map(|expression| Regex::new(expression).unwrap())
        .collect();
    let matcher = GroupedMatcher::replicas(&rules, 1).unwrap().pop().unwrap();
    let duplicate = matcher
        .groups
        .iter()
        .find(|group| group.rule_ids.as_ref() == [0, 1])
        .unwrap();
    assert!(matches!(duplicate.engine, GroupEngine::Primitive(_)));
    let mut inputs = vec![
        b"GET /\r\n\r\ntoken\0".to_vec(),
        b"alphaxx".to_vec(),
        b"beta123".to_vec(),
        b"version-----1.2".to_vec(),
    ];
    let mut seed = 1u64;
    let alphabet = [
        0, 255, b'\n', b'a', b'b', b'c', b'A', b'B', b'C', b'@', b' ',
    ];
    for length in 0..=160 {
        for _ in 0..16 {
            inputs.push(
                (0..length)
                    .map(|_| {
                        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                        alphabet[(seed >> 32) as usize % alphabet.len()]
                    })
                    .collect(),
            );
        }
    }
    for input in inputs {
        let expected: Vec<_> = regexes
            .iter()
            .enumerate()
            .filter_map(|(id, regex)| regex.is_match(&input).then_some(id))
            .collect();
        assert_eq!(
            matcher.matching_rules(&input),
            expected,
            "len={}",
            input.len()
        );
    }
}

#[test]
fn literal_tail_recognition_preserves_offsets_overlaps_and_flags() {
    for expression in [
        "(?s-u:^.*version.....([\\.\\d]+))",
        "(?s-u:^.*aa[b]+)",
        "(?s-u:^.*\\x00a.{2}[\\x80-\\xff]+)",
    ] {
        let predicate = LiteralTail::from_hir(&hir(expression)).unwrap();
        let finder = Finder::new(&predicate.literal);
        let regex = Regex::new(expression).unwrap();
        let mut inputs = vec![
            b"aaab".to_vec(),
            b"version-----X version-----1".to_vec(),
            b"versionversion---1".to_vec(),
            Vec::new(),
        ];
        for prefix in 0..13 {
            for gap in 0..8 {
                for last in [0, b'.', b'0', b'9', b'x', b'b', 255] {
                    let mut bytes = vec![b'\n'; prefix];
                    bytes.extend_from_slice(&predicate.literal);
                    bytes.extend(std::iter::repeat_n(255, gap));
                    bytes.push(last);
                    inputs.push(bytes);
                }
            }
        }
        for input in inputs {
            assert_eq!(
                predicate.matches(&input, &finder),
                regex.is_match(&input),
                "{expression}, {input:?}"
            );
        }
    }
    for expression in [
        "(?-u:^.*version.....([\\.\\d]+))",
        "(?su:^.*version.....([\\.\\d]+))",
        "(?s-u:^.*version.....([\\.\\d]+)$)",
        "(?s-u:^.*version.....([\\.\\d]{2,}))",
        "(?is-u:^.*version.....([\\.\\d]+))",
        "(?s-u:^.*version.{1,5}[0-9]+)",
    ] {
        assert!(
            LiteralTail::from_hir(&hir(expression)).is_none(),
            "{expression}"
        );
    }
}
