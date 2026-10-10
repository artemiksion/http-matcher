use std::fmt;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::normalize::{normalize, Request};

#[derive(Debug, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    #[serde(alias = "uri")]
    pub url: String,
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    #[serde(default, alias = "body")]
    pub data: serde_json::Value,
}

#[derive(Default)]
pub struct ReadStats {
    pub requests: usize,
    pub normalization_time: Duration,
}

pub fn read_requests(
    input_path: &Path,
    limit: Option<usize>,
    mut on_request: impl FnMut(Request) -> Result<()>,
) -> Result<ReadStats> {
    if limit == Some(0) {
        return Ok(ReadStats::default());
    }

    let mut input_files = Vec::new();
    collect_json_files(input_path, &mut input_files)?;
    input_files.sort();
    ensure!(
        !input_files.is_empty(),
        "no JSON files in {}",
        input_path.display()
    );

    let mut processed_requests = 0;
    let mut normalization_time = Duration::ZERO;
    for input_file in input_files {
        let file =
            File::open(&input_file).with_context(|| format!("open {}", input_file.display()))?;

        let outcome = stream_array(BufReader::new(file), &mut |http_request| {
            let request_id = processed_requests as u64;
            let normalization_start = Instant::now();
            let request = normalize(http_request, request_id);
            normalization_time += normalization_start.elapsed();
            on_request(request).with_context(|| format!("process request {request_id}"))?;
            processed_requests += 1;

            if limit.is_some_and(|limit| processed_requests >= limit) {
                Ok(ControlFlow::Break(()))
            } else {
                Ok(ControlFlow::Continue(()))
            }
        })
        .with_context(|| format!("read {}", input_file.display()))?;

        if outcome.is_break() {
            break;
        }
    }

    Ok(ReadStats {
        requests: processed_requests,
        normalization_time,
    })
}

pub(crate) fn collect_json_files(input_path: &Path, input_files: &mut Vec<PathBuf>) -> Result<()> {
    let metadata =
        fs::metadata(input_path).with_context(|| format!("inspect {}", input_path.display()))?;
    if metadata.is_file() {
        input_files.push(input_path.to_owned());
        return Ok(());
    }
    ensure!(
        metadata.is_dir(),
        "{} is not a file or directory",
        input_path.display()
    );

    for entry in
        fs::read_dir(input_path).with_context(|| format!("list {}", input_path.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let entry_path = entry.path();
        if file_type.is_dir() {
            collect_json_files(&entry_path, input_files)?;
        } else if file_type.is_file()
            && entry_path
                .extension()
                .is_some_and(|extension| extension == "json")
        {
            input_files.push(entry_path);
        }
    }
    Ok(())
}

struct RequestVisitor<'a, F> {
    on_request: &'a mut F,
    stopped: &'a mut bool,
    callback_error: &'a mut Option<anyhow::Error>,
}

impl<'de, F> Visitor<'de> for RequestVisitor<'_, F>
where
    F: FnMut(HttpRequest) -> Result<ControlFlow<()>>,
{
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of HTTP requests")
    }

    fn visit_seq<S>(self, mut requests: S) -> std::result::Result<(), S::Error>
    where
        S: SeqAccess<'de>,
    {
        while let Some(request) = requests.next_element()? {
            match (self.on_request)(request) {
                Ok(ControlFlow::Continue(())) => {}
                Ok(ControlFlow::Break(())) => {
                    // Returning normally would require consuming the rest of the array.
                    *self.stopped = true;
                    return Err(S::Error::custom("request limit reached"));
                }
                Err(error) => {
                    *self.callback_error = Some(error);
                    return Err(S::Error::custom("request processing failed"));
                }
            }
        }
        Ok(())
    }
}

fn stream_array(
    reader: impl Read,
    on_request: &mut impl FnMut(HttpRequest) -> Result<ControlFlow<()>>,
) -> Result<ControlFlow<()>> {
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let mut stopped = false;
    let mut callback_error = None;
    let result = deserializer.deserialize_seq(RequestVisitor {
        on_request,
        stopped: &mut stopped,
        callback_error: &mut callback_error,
    });

    if let Some(error) = callback_error {
        return Err(error);
    }
    if stopped {
        return Ok(ControlFlow::Break(()));
    }
    result?;
    deserializer.end()?;
    Ok(ControlFlow::Continue(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST: &str = r#"{"method":"GET","url":"/","headers":{},"data":""}"#;

    #[test]
    fn streams_requests_and_ignores_metadata() {
        let input =
            format!("[{REQUEST},{{\"method\":\"POST\",\"uri\":\"/login\",\"metadata\":true}}]");
        let mut requests = Vec::new();
        let outcome = stream_array(input.as_bytes(), &mut |request| {
            requests.push(request);
            Ok(ControlFlow::Continue(()))
        })
        .unwrap();

        assert!(outcome.is_continue());
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].url, "/login");
        assert!(requests[1].data.is_null());
    }
}
