use serde_json::Value;

use crate::corpus::HttpRequest;

#[derive(Debug)]
pub struct Request {
    pub id: u64,
    pub bytes: Vec<u8>,
}

pub fn normalize(request: HttpRequest, id: u64) -> Request {
    let mut headers: Vec<_> = request
        .headers
        .into_iter()
        .map(|(mut name, value)| {
            name.make_ascii_lowercase();
            (name, value)
        })
        .collect();
    headers.sort_by(|left, right| left.0.cmp(&right.0));

    let body_length = request.data.as_str().map_or(0, str::len);
    let capacity = request.method.len()
        + 1
        + request.url.len()
        + 4
        + headers
            .iter()
            .map(|(name, value)| name.len() + value.len() + 4)
            .sum::<usize>()
        + body_length;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(request.method.as_bytes());
    bytes.push(b' ');
    bytes.extend_from_slice(request.url.as_bytes());
    bytes.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");

    match request.data {
        Value::Null => {}
        Value::String(body) => bytes.extend_from_slice(body.as_bytes()),
        // The corpus may represent structured bodies; use compact JSON for them.
        body => bytes.extend_from_slice(body.to_string().as_bytes()),
    }

    Request { id, bytes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_headers_and_preserves_request_values() {
        let request = serde_json::from_str(
            r#"{
            "method":"POST",
            "url":"/Login?value=%2F",
            "headers":{"Z-Token":"AbC","Host":"Example.COM","a-header":"Value"},
            "data":"Body\u0000é"
        }"#,
        )
        .unwrap();

        let normalized = normalize(request, 42);
        assert_eq!(normalized.id, 42);
        assert_eq!(normalized.bytes, "POST /Login?value=%2F\r\na-header: Value\r\nhost: Example.COM\r\nz-token: AbC\r\n\r\nBody\0é".as_bytes());

        for (body, expected) in [("null", ""), (r#"{"key":[1,true]}"#, r#"{"key":[1,true]}"#)] {
            let request =
                serde_json::from_str(&format!(r#"{{"method":"GET","url":"/","data":{body}}}"#))
                    .unwrap();
            let normalized = normalize(request, 0);
            assert_eq!(
                normalized.bytes,
                format!("GET /\r\n\r\n{expected}").as_bytes()
            );
        }
    }
}
