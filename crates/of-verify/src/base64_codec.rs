//! Strict RFC 4648 base64 codec (matching Python's `base64.b64decode(..., validate=True)`)
//! and canonical ASCII JSON encoding matching Python's `json.dumps(..., sort_keys=True,
//! separators=(",", ":"))` plus PEP 383 `surrogateescape` JSON string encoding.

use serde_json::Value;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let has_b1 = i + 1 < input.len();
        let has_b2 = i + 2 < input.len();
        let b1 = if has_b1 { input[i + 1] as u32 } else { 0 };
        let b2 = if has_b2 { input[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        out.push(if has_b1 {
            ALPHABET[((triple >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if has_b2 {
            ALPHABET[(triple & 0x3F) as usize] as char
        } else {
            '='
        });
        i += 3;
    }
    out
}

fn decode_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

pub fn decode_strict(input: &str) -> Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return Err("Incorrect padding".to_string());
    }
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    let chunks = bytes.len() / 4;
    for chunk_idx in 0..chunks {
        let c = &bytes[chunk_idx * 4..chunk_idx * 4 + 4];
        let is_last = chunk_idx + 1 == chunks;
        let v0 = decode_val(c[0]).ok_or_else(|| "Non-base64 digit found".to_string())?;
        let v1 = decode_val(c[1]).ok_or_else(|| "Non-base64 digit found".to_string())?;
        if c[2] == b'=' {
            if !is_last || c[3] != b'=' {
                return Err("Excess data after padding".to_string());
            }
            out.push((v0 << 2) | (v1 >> 4));
        } else if c[3] == b'=' {
            if !is_last {
                return Err("Excess data after padding".to_string());
            }
            let v2 = decode_val(c[2]).ok_or_else(|| "Non-base64 digit found".to_string())?;
            out.push((v0 << 2) | (v1 >> 4));
            out.push(((v1 & 0x0F) << 4) | (v2 >> 2));
        } else {
            let v2 = decode_val(c[2]).ok_or_else(|| "Non-base64 digit found".to_string())?;
            let v3 = decode_val(c[3]).ok_or_else(|| "Non-base64 digit found".to_string())?;
            out.push((v0 << 2) | (v1 >> 4));
            out.push(((v1 & 0x0F) << 4) | (v2 >> 2));
            out.push(((v2 & 0x03) << 6) | v3);
        }
    }
    Ok(out)
}

/// Escape a UTF-8 string exactly like Python `json.dumps(s, ensure_ascii=True)`.
pub fn push_json_str_ascii(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) <= 0x7E => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
        }
    }
    out.push('"');
}

/// Escape raw OS path bytes like Python `json.dumps(os.fsdecode(raw), ensure_ascii=True)`:
/// valid UTF-8 characters are escaped normally; invalid bytes (`0x80..=0xFF`) are emitted
/// as `\udcXX` matching PEP 383 `surrogateescape`.
pub fn push_json_bytes_surrogate(out: &mut String, raw: &[u8]) {
    out.push('"');
    let mut rest = raw;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                for ch in valid.chars() {
                    push_escaped_char_ascii(out, ch);
                }
                break;
            }
            Err(err) => {
                let valid_len = err.valid_up_to();
                if valid_len > 0 {
                    if let Ok(valid) = std::str::from_utf8(&rest[..valid_len]) {
                        for ch in valid.chars() {
                            push_escaped_char_ascii(out, ch);
                        }
                    }
                }
                let bad_len = err.error_len().unwrap_or(1);
                for &b in &rest[valid_len..valid_len + bad_len] {
                    out.push_str(&format!("\\udc{:02x}", b));
                }
                rest = &rest[valid_len + bad_len..];
            }
        }
    }
    out.push('"');
}

fn push_escaped_char_ascii(out: &mut String, ch: char) {
    match ch {
        '"' => out.push_str("\\\""),
        '\\' => out.push_str("\\\\"),
        '\u{08}' => out.push_str("\\b"),
        '\u{0C}' => out.push_str("\\f"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
        c if (c as u32) <= 0x7E => out.push(c),
        c => {
            let mut buf = [0u16; 2];
            for unit in c.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{:04x}", unit));
            }
        }
    }
}

/// Deterministic JSON serialization matching Python `json.dumps(val, sort_keys=True,
/// separators=(",", ":"), ensure_ascii=True)`.
pub fn canonical_json(val: &Value) -> String {
    let mut out = String::new();
    write_json_value(&mut out, val, ",", ":", true);
    out
}

/// JSON serialization matching Python `json.dumps(val, separators=(", ", ": "), ensure_ascii=True)`
/// (preserves `serde_json::Map` key order, which is sorted when `BTreeMap` is used).
pub fn python_spaced_json(val: &Value) -> String {
    let mut out = String::new();
    write_json_value(&mut out, val, ", ", ": ", false);
    out
}

fn write_json_value(out: &mut String, val: &Value, item_sep: &str, kv_sep: &str, sort_keys: bool) {
    match val {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => push_json_str_ascii(out, s),
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                write_json_value(out, item, item_sep, kv_sep, sort_keys);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            if sort_keys {
                keys.sort();
            }
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                push_json_str_ascii(out, k);
                out.push_str(kv_sep);
                if let Some(v) = map.get(*k) {
                    write_json_value(out, v, item_sep, kv_sep, sort_keys);
                }
            }
            out.push('}');
        }
    }
}
