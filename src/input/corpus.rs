use std::fmt;
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::normalize::{normalize, Request};

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

// Each raw file is buffered before decoding. Larger files use the streaming
// fallback to bound extra input memory while the prepared corpus grows.
const FILE_BUFFER_LIMIT: u64 = 1024 * 1024 * 1024;

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
        let mut file =
            File::open(&input_file).with_context(|| format!("open {}", input_file.display()))?;
        let mut callback = |http_request| {
            let request_id = processed_requests as u64;
            let start = Instant::now();
            let request = normalize(http_request, request_id);
            normalization_time += start.elapsed();
            on_request(request).with_context(|| format!("process request {request_id}"))?;
            processed_requests += 1;
            if limit.is_some_and(|limit| processed_requests >= limit) {
                Ok(ControlFlow::Break(()))
            } else {
                Ok(ControlFlow::Continue(()))
            }
        };
        let outcome = buffered_array(&mut file, FILE_BUFFER_LIMIT, &mut callback)
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
        loop {
            let request = requests.next_element()?;
            let Some(request) = request else { break };
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
    visit_array(
        &mut serde_json::Deserializer::from_reader(reader),
        on_request,
    )
}

fn buffered_array(
    file: &mut File,
    buffer_limit: u64,
    on_request: &mut impl FnMut(HttpRequest) -> Result<ControlFlow<()>>,
) -> Result<ControlFlow<()>> {
    let length = file.metadata()?.len();
    if length > buffer_limit {
        return stream_array(BufReader::new(file), on_request);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    // Limit the read even when the file grows after inspecting its metadata.
    file.take(buffer_limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > buffer_limit {
        file.seek(SeekFrom::Start(0))?;
        drop(bytes);
        return stream_array(BufReader::new(file), on_request);
    }
    if let Ok(text) = std::str::from_utf8(&bytes) {
        return visit_array(&mut serde_json::Deserializer::from_str(text), on_request);
    }
    // Ignored JSON fields may contain invalid UTF-8 accepted by from_slice.
    // Keep this fallback; invalid typed fields must still be rejected.
    visit_array(
        &mut serde_json::Deserializer::from_slice(&bytes),
        on_request,
    )
}

fn visit_array<'de, R: serde_json::de::Read<'de>>(
    deserializer: &mut serde_json::Deserializer<R>,
    on_request: &mut impl FnMut(HttpRequest) -> Result<ControlFlow<()>>,
) -> Result<ControlFlow<()>> {
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

    #[test]
    fn slice_visitor_preserves_limits_callback_errors_and_trailing_validation() {
        let input = format!("[{REQUEST},{REQUEST}] true");
        for buffered in [false, true] {
            let run = |callback: &mut dyn FnMut(HttpRequest) -> Result<ControlFlow<()>>| {
                let mut callback = |request| callback(request);
                if buffered {
                    visit_array(
                        &mut serde_json::Deserializer::from_slice(input.as_bytes()),
                        &mut callback,
                    )
                } else {
                    stream_array(input.as_bytes(), &mut callback)
                }
            };
            let mut count = 0;
            assert!(run(&mut |_| {
                count += 1;
                Ok(ControlFlow::Break(()))
            })
            .unwrap()
            .is_break());
            assert_eq!(count, 1);
            assert!(run(&mut |_| Ok(ControlFlow::Continue(()))).is_err());
            let error = run(&mut |_| anyhow::bail!("callback detail")).unwrap_err();
            assert_eq!(error.to_string(), "callback detail");
        }
    }

    #[test]
    fn oversized_file_falls_back_to_the_same_streamed_requests() {
        let path = std::env::temp_dir().join(format!(
            "matcher-reader-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, format!("[{REQUEST},{REQUEST}]")).unwrap();
        for budget in [1, 4096] {
            let mut file = File::open(&path).unwrap();
            let mut count = 0;
            assert!(buffered_array(&mut file, budget, &mut |_| {
                count += 1;
                Ok(ControlFlow::Continue(()))
            })
            .unwrap()
            .is_continue());
            assert_eq!(count, 2);
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn prevalidated_reader_preserves_ignored_invalid_utf8_and_rejects_typed_invalid_utf8() {
        let path = std::env::temp_dir().join(format!(
            "matcher-prevalidated-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut input = br#"[{"method":"GET","url":"/","metadata":""#.to_vec();
        input.push(255);
        input.extend_from_slice(br#""}]"#);
        fs::write(&path, &input).unwrap();
        let requests: Vec<HttpRequest> = serde_json::from_slice(&input).unwrap();
        let expected: Vec<_> = requests
            .into_iter()
            .enumerate()
            .map(|(id, request)| normalize(request, id as u64).bytes)
            .collect();
        let mut actual = Vec::new();
        read_requests(&path, None, |request| {
            actual.push(request.bytes);
            Ok(())
        })
        .unwrap();
        assert_eq!(actual, expected);
        let mut invalid_url = br#"[{"method":"GET","url":""#.to_vec();
        invalid_url.push(255);
        invalid_url.extend_from_slice(br#""}]"#);
        fs::write(&path, invalid_url).unwrap();
        assert!(read_requests(&path, None, |_| Ok(())).is_err());
        fs::remove_file(path).unwrap();
    }
}
