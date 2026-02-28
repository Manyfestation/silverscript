use silverscript_lang::debug_info::SourceSpan;

use crate::session::{DebugValue, FailureReport};

#[derive(Debug, Clone)]
pub struct SourceContextLine {
    pub line: u32,
    pub text: String,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct SourceContext {
    pub lines: Vec<SourceContextLine>,
}

pub fn build_source_context(source_lines: &[String], span: SourceSpan, radius: usize) -> SourceContext {
    let line = span.line.saturating_sub(1) as usize;
    let start = line.saturating_sub(radius);
    let end = (line + radius).min(source_lines.len().saturating_sub(1));

    let mut lines = Vec::new();
    for idx in start..=end {
        let display_line = idx + 1;
        let content = source_lines.get(idx).map(String::as_str).unwrap_or("");
        lines.push(SourceContextLine { line: display_line as u32, text: content.to_string(), is_active: idx == line });
    }

    SourceContext { lines }
}

pub fn format_value(type_name: &str, value: &DebugValue) -> String {
    let element_type = type_name.strip_suffix("[]");
    match (type_name, value) {
        ("int", DebugValue::Int(number)) => number.to_string(),
        ("bool", DebugValue::Bool(value)) => value.to_string(),
        ("string", DebugValue::String(value)) => value.clone(),
        (_, DebugValue::Unknown(reason)) => unavailable_reason(reason),
        (_, DebugValue::Bytes(bytes)) if element_type.is_some() => {
            let element_type = element_type.expect("checked");
            let Some(element_size) = array_element_size(element_type) else {
                return format!("0x{}", encode_hex(bytes));
            };
            if element_size == 0 || bytes.len() % element_size != 0 {
                return format!("0x{}", encode_hex(bytes));
            }

            let mut values: Vec<String> = Vec::new();
            for chunk in bytes.chunks(element_size) {
                let decoded = match element_type {
                    "int" => DebugValue::Int(decode_i64(chunk).unwrap_or(0)),
                    "bool" => DebugValue::Bool(decode_i64(chunk).unwrap_or(0) != 0),
                    _ => DebugValue::Bytes(chunk.to_vec()),
                };
                values.push(format_value(element_type, &decoded));
            }
            format!("[{}]", values.join(", "))
        }
        (_, DebugValue::Bytes(bytes)) => format!("0x{}", encode_hex(bytes)),
        (_, DebugValue::Int(number)) => number.to_string(),
        (_, DebugValue::Bool(value)) => value.to_string(),
        (_, DebugValue::String(value)) => value.clone(),
        (_, DebugValue::Array(values)) => {
            let value_type = element_type.unwrap_or(type_name);
            format!("[{}]", values.iter().map(|v| format_value(value_type, v)).collect::<Vec<_>>().join(", "))
        }
    }
}

fn unavailable_reason(reason: &str) -> String {
    if reason.trim().is_empty() {
        "<unavailable>".to_string()
    } else if reason.contains("failed to compile debug expression")
        || reason.contains("undefined identifier")
        || reason.contains("__arg_")
    {
        "<unavailable: depends on inlined function call internals>".to_string()
    } else if reason.contains("failed to execute shadow script") {
        "<unavailable: runtime evaluation failed>".to_string()
    } else {
        format!("<unavailable: {}>", concise_reason(reason))
    }
}

/// Truncates error messages to 96 chars for display in debugger UI.
fn concise_reason(reason: &str) -> String {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return "unknown".to_string();
    }
    let first_line = trimmed.lines().next().unwrap_or(trimmed);
    const MAX_CHARS: usize = 96;
    if first_line.chars().count() <= MAX_CHARS {
        first_line.to_string()
    } else {
        let mut out = String::new();
        for ch in first_line.chars().take(MAX_CHARS) {
            out.push(ch);
        }
        out.push_str("...");
        out
    }
}

fn array_element_size(element_type: &str) -> Option<usize> {
    match element_type {
        "int" => Some(8),
        "bool" => Some(1),
        "byte" => Some(1),
        other => other.strip_prefix("bytes").and_then(|v| v.parse::<usize>().ok()),
    }
}

fn decode_i64(bytes: &[u8]) -> Result<i64, String> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() > 8 {
        return Err("numeric value is longer than 8 bytes".to_string());
    }
    let msb = bytes[bytes.len() - 1];
    let sign = 1 - 2 * ((msb >> 7) as i64);
    let first_byte = (msb & 0x7f) as i64;
    let mut value = first_byte;
    for byte in bytes[..bytes.len() - 1].iter().rev() {
        value = (value << 8) + (*byte as i64);
    }
    Ok(value * sign)
}

/// Renders a `FailureReport` as a Rust-style diagnostic string.
///
/// Example output:
/// ```text
/// error: require() failed
///   --> 8:5
///    |
///  7 | int right = left * 2;
///  8 | require(right > left);
///    | ^^^^^^^^^^^^^^^^^^^^^^ verification failed here
///    |   right = 4, left = 4
///    |
///   ::: called from main
///    |
/// 12 | check_pair(a, b);
///    | ^^^^^^^^^^^^^^^^^ in this call
/// ```
pub fn format_failure_report(report: &FailureReport, format_var: &dyn Fn(&str, &DebugValue) -> String) -> String {
    let source_lines: Vec<&str> = report.source_text.lines().collect();
    let mut out = String::new();

    // Find the widest line number across all frames for consistent alignment.
    let max_line = report.frames.iter().filter_map(|f| f.span.map(|s| s.line)).max().unwrap_or(1);
    let w = format!("{max_line}").len().max(2);
    let pad = " ".repeat(w);

    out.push_str(&format!("error: {}\n", report.message));

    for (frame_idx, frame) in report.frames.iter().enumerate() {
        let Some(span) = frame.span else {
            continue;
        };

        let line_idx = span.line.saturating_sub(1) as usize;

        if frame_idx == 0 {
            out.push_str(&format!("{pad} --> {}:{}\n", span.line, span.col));
        } else {
            out.push_str(&format!("{pad} ::: called from {}\n", frame.function_name));
        }

        out.push_str(&format!("{pad} |\n"));

        // Show one context line before the active line.
        if line_idx > 0 {
            if let Some(prev) = source_lines.get(line_idx - 1) {
                out.push_str(&format!("{:>w$} | {prev}\n", span.line - 1));
            }
        }

        if let Some(line_text) = source_lines.get(line_idx) {
            out.push_str(&format!("{:>w$} | {line_text}\n", span.line));

            // Underline from col to end_col.
            let start_col = span.col.saturating_sub(1) as usize;
            let end_col = if span.end_line == span.line && span.end_col > span.col {
                span.end_col.saturating_sub(1) as usize
            } else {
                line_text.len()
            };
            let underline_len = end_col.saturating_sub(start_col).max(1);
            let marker_pad = " ".repeat(start_col);
            let underline = "^".repeat(underline_len);
            let label = if frame_idx == 0 { " verification failed here" } else { " in this call" };
            out.push_str(&format!("{pad} | {marker_pad}{underline}{label}\n"));

            // Variable values on the next line.
            if !frame.variables.is_empty() {
                let vars_str = frame
                    .variables
                    .iter()
                    .map(|var| format!("{} = {}", var.name, format_var(&var.type_name, &var.value)))
                    .collect::<Vec<_>>()
                    .join(", ");
                out.push_str(&format!("{pad} |   {vars_str}\n"));
            }
        }

        out.push_str(&format!("{pad} |\n"));
    }

    out
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = vec![0u8; bytes.len() * 2];
    if faster_hex::hex_encode(bytes, &mut out).is_err() {
        return String::new();
    }
    String::from_utf8(out).unwrap_or_default()
}
