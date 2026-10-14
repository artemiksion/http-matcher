//! Parse Nmap rules, compile supported expressions, and record skipped rules.

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use regex::bytes::{Regex, RegexBuilder};
use serde::Serialize;

pub const PATTERNS_PATH: &str = "data/nmap-service-probes";
const REGEX_SIZE_LIMIT: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    Match,
    Softmatch,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub service: String,
    pub kind: MatchKind,
    pub probe_order: usize,
    pub line_number: usize,
    pub expression: String,
}

#[derive(Debug)]
pub struct PatternDatabase {
    pub rules: Vec<Rule>,
    pub regexes: Vec<Regex>,
    pub skipped: Vec<SkippedRule>,
}

#[derive(Debug, Serialize)]
pub struct SkippedRule {
    #[serde(rename = "line")]
    pub line_number: usize,
    pub service: String,
    pub probe: String,
    pub reason: String,
}

impl PatternDatabase {
    pub fn load(path: &Path) -> io::Result<Self> {
        Self::from_reader(BufReader::new(File::open(path)?))
    }

    fn from_reader(reader: impl BufRead) -> io::Result<Self> {
        let mut database = Self {
            rules: Vec::new(),
            regexes: Vec::new(),
            skipped: Vec::new(),
        };
        let mut current_probe = None;
        let mut probe_count = 0;

        for (line_index, line) in reader.lines().enumerate() {
            let line_number = line_index + 1;
            let line = line?;
            let (directive, arguments) = take_word(line.trim_start());

            if directive == "Probe" {
                let (protocol, remaining) = take_word(arguments);
                let (probe_name, payload) = take_word(remaining);
                if !matches!(protocol, "TCP" | "UDP") || probe_name.is_empty() {
                    return Err(parse_error(
                        line_number,
                        "expected Probe TCP|UDP <name> q<...>",
                    ));
                }
                delimited_content(payload, b'q', line_number)?;
                current_probe = Some((probe_name.to_owned(), probe_count));
                probe_count += 1;
                continue;
            }

            let kind = match directive {
                "match" => MatchKind::Match,
                "softmatch" => MatchKind::Softmatch,
                _ => continue,
            };
            let (probe, probe_order) = current_probe.as_ref().ok_or_else(|| {
                parse_error(line_number, "match rule appears before the first Probe")
            })?;
            let (service, pattern) = take_word(arguments);
            if service.is_empty() {
                return Err(parse_error(line_number, "missing service name"));
            }
            let (pattern, suffix) = delimited_content(pattern, b'm', line_number)?;
            // Version fields follow whitespace; only adjacent i/s belong to the regex.
            let flags_end = suffix.find(char::is_whitespace).unwrap_or(suffix.len());
            let flags = &suffix[..flags_end];
            if !flags.bytes().all(|flag| matches!(flag, b'i' | b's')) {
                return Err(parse_error(
                    line_number,
                    "regex flags must contain only i and s",
                ));
            }

            let mut enabled_flags = String::new();
            if flags.contains('i') {
                enabled_flags.push('i');
            }
            if flags.contains('s') {
                enabled_flags.push('s');
            }
            let expression = format!("(?{enabled_flags}-u:{})", normalize_octal(pattern));
            match compile_pattern(pattern, &expression) {
                Ok(regex) => {
                    database.rules.push(Rule {
                        service: service.to_owned(),
                        kind,
                        probe_order: *probe_order,
                        line_number,
                        expression,
                    });
                    database.regexes.push(regex);
                }
                Err(reason) => database.skipped.push(SkippedRule {
                    line_number,
                    service: service.to_owned(),
                    probe: probe.clone(),
                    reason,
                }),
            }
        }

        Ok(database)
    }
}

fn compile_pattern(pattern: &str, expression: &str) -> Result<Regex, String> {
    let regex = RegexBuilder::new(expression)
        .unicode(false)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|error| {
            error
                .to_string()
                .lines()
                .last()
                .unwrap_or("invalid regex")
                .trim_start_matches("error: ")
                .to_owned()
        })?;
    if has_possessive_quantifier(pattern) {
        return Err("possessive quantifiers have different semantics in Rust regex".to_owned());
    }
    Ok(regex)
}

fn take_word(input: &str) -> (&str, &str) {
    let input = input.trim_start();
    let word_end = input.find(char::is_whitespace).unwrap_or(input.len());
    (&input[..word_end], input[word_end..].trim_start())
}

fn delimited_content(input: &str, prefix: u8, line_number: usize) -> io::Result<(&str, &str)> {
    let bytes = input.as_bytes();
    if bytes.len() < 3 || bytes[0] != prefix || !bytes[1].is_ascii_graphic() {
        return Err(parse_error(line_number, "missing delimited expression"));
    }
    let delimiter = bytes[1] as char;
    // Nmap closes at the first delimiter, even if preceded by a backslash.
    let expression_end = input[2..]
        .find(delimiter)
        .map(|offset| offset + 2)
        .ok_or_else(|| parse_error(line_number, "missing closing delimiter"))?;
    Ok((&input[2..expression_end], &input[expression_end + 1..]))
}

fn normalize_octal(pattern: &str) -> String {
    let mut normalized = String::with_capacity(pattern.len());
    let mut characters = pattern.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\\' {
            normalized.push(character);
            continue;
        }
        match characters.next() {
            Some('0') => {
                // PCRE treats \0 plus at most two octal digits as a byte escape.
                let mut byte = 0u8;
                for _ in 0..2 {
                    match characters.peek().copied() {
                        Some(digit @ '0'..='7') => {
                            byte = byte * 8 + (digit as u8 - b'0');
                            characters.next();
                        }
                        _ => break,
                    }
                }
                normalized.push_str(&format!("\\x{byte:02X}"));
            }
            Some(escaped) => {
                normalized.push('\\');
                normalized.push(escaped);
            }
            None => normalized.push('\\'),
        }
    }
    normalized
}

fn has_possessive_quantifier(pattern: &str) -> bool {
    let mut characters = pattern.char_indices().peekable();
    let mut class_start = None;
    while let Some((position, character)) = characters.next() {
        if character == '\\' {
            characters.next();
            continue;
        }
        if let Some(start) = class_start {
            // Keep POSIX classes such as [[:digit:]] inside the surrounding class.
            if character == '[' && characters.peek().is_some_and(|(_, next)| *next == ':') {
                for (_, next) in characters.by_ref() {
                    if next == ']' {
                        break;
                    }
                }
            } else if character == ']'
                && position > start + 1
                && !(position == start + 2 && pattern.as_bytes()[start + 1] == b'^')
            {
                class_start = None;
            }
            continue;
        }
        if character == '[' {
            class_start = Some(position);
        } else if matches!(character, '*' | '+' | '?')
            && characters.peek().is_some_and(|(_, next)| *next == '+')
        {
            return true;
        } else if character == '{' {
            if let Some((counts, suffix)) = pattern[position + 1..].split_once('}') {
                if suffix.starts_with('+')
                    && counts.bytes().any(|byte| byte.is_ascii_digit())
                    && counts
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b',')
                {
                    return true;
                }
            }
        }
    }
    false
}

fn parse_error(line_number: usize, message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("nmap-service-probes line {line_number}: {message}"),
    )
}

#[cfg(test)]
mod tests {
    use super::{MatchKind, PatternDatabase};

    #[test]
    fn preserves_flags_and_probe_order() {
        let input = b"Probe TCP NULL q||\nmatch http m|^get.foo$|is p/Product/\n\
                      Probe UDP Query q%hello%\nsoftmatch dns m@^reply$@\n";
        let database = PatternDatabase::from_reader(&input[..]).unwrap();

        assert!(database.regexes[0].is_match(b"GET\nfoo"));
        assert!(database.regexes[0].is_match(b"GET\xFFfoo"));
        assert_eq!(database.rules[0].probe_order, 0);
        assert_eq!(database.rules[1].probe_order, 1);
        assert_eq!(database.rules[1].kind, MatchKind::Softmatch);
    }

    #[test]
    fn reports_unsupported_regex_without_losing_supported_rules() {
        let input = br"Probe TCP Test q||
match backreference m|^(a)\1$|
match lookahead m|^(?=GET)GET|
match possessive m|a++|
match http m|^GET |
";
        let database = PatternDatabase::from_reader(&input[..]).unwrap();

        assert_eq!(database.skipped.len(), 3);
        assert_eq!(database.skipped[0].line_number, 2);
        assert_eq!(database.rules.len(), 1);
        assert_eq!(database.regexes.len(), database.rules.len());
        assert!(database.regexes[0].is_match(b"GET /"));
    }
}
