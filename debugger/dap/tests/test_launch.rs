mod harness;

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use harness::TestClient;
use serde_json::json;

const SIMPLE_SCRIPT: &str = r#"pragma silverscript ^0.1.0;

contract Simple() {
    entrypoint function main() {
        int a = 1;
        int b = 2;
        require(a + b == 3);
    }
}
"#;

const MULTIFUNCTION_IF_STATEMENTS_SCRIPT: &str = r#"pragma silverscript ^0.1.0;

contract MultiFunctionIfStatements(int x, int y) {
    entrypoint function transfer(int a, int b) {
        int d = a + b;
        d = d - a;
        if (d == x) {
            int c = d + b;
            d = a + c;
            require(c > d);
        } else {
            d = a;
        }
        d = d + a;
        require(d == y);
    }

    entrypoint function timeout(int b) {
        int d = b;
        d = d + 2;
        if (d == x) {
            int c = d + b;
            d = c + d;
            require(c > d);
        }
        d = b;
        require(d == y);
    }
}
"#;

const INLINE_CALL_BOUNCE_SCRIPT: &str = r#"pragma silverscript ^0.1.0;

contract InlineBounce() {
    function check_pair(int leftInput, int rightInput) {
        int left = leftInput + rightInput;
        int right = left * 2;
        require(right >= left);
    }

    entrypoint function main(int a, int b) {
        check_pair(a, b);
        require(a >= 0);
    }
}
"#;


struct TempScript {
    path: PathBuf,
}

impl TempScript {
    fn new(source: &str) -> Self {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_nanos()).unwrap_or_default();
        let file_name = format!("silverscript-dap-test-{}-{}.sil", std::process::id(), unique);
        let path = std::env::temp_dir().join(file_name);
        fs::write(&path, source).expect("failed to write temp script");
        Self { path }
    }

    fn path_str(&self) -> String {
        self.path.to_string_lossy().to_string()
    }
}

impl Drop for TempScript {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn equivalent_path_variant(path: &str) -> String {
    let path_buf = PathBuf::from(path);
    let Some(parent) = path_buf.parent() else {
        return path.to_string();
    };
    let Some(parent_name) = parent.file_name() else {
        return path.to_string();
    };
    let Some(file_name) = path_buf.file_name() else {
        return path.to_string();
    };
    parent.join("..").join(parent_name).join(file_name).to_string_lossy().to_string()
}

#[test]
fn launch_stops_on_entry_and_disconnects() {
    let script = TempScript::new(SIMPLE_SCRIPT);
    let script_path = script.path_str();

    let mut client = TestClient::spawn();
    let stopped = client.full_launch_sequence(&script_path);

    let reason = stopped.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(reason, "entry");

    client.send_request("threads", serde_json::Value::Null);
    let threads = client.expect_response_success("threads");
    let size = threads.get("body").and_then(|v| v.get("threads")).and_then(|v| v.as_array()).map(|arr| arr.len()).unwrap_or(0);
    assert!(size >= 1);

    client.send_request("disconnect", serde_json::json!({}));
    client.expect_response_success("disconnect");
}

#[test]
fn breakpoint_snaps_and_continue_stops() {
    let script = TempScript::new(SIMPLE_SCRIPT);
    let script_path = script.path_str();

    let mut client = TestClient::spawn();

    client.send_request(
        "initialize",
        json!({
            "adapterID": "silverscript",
            "pathFormat": "path",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "supportsVariableType": true,
            "supportsVariablePaging": false,
            "supportsRunInTerminalRequest": false
        }),
    );
    client.expect_response_success("initialize");
    client.expect_event("initialized");

    client.send_request(
        "launch",
        json!({
            "scriptPath": script_path,
            "stopOnEntry": true
        }),
    );
    client.expect_response_success("launch");

    client.send_request(
        "setBreakpoints",
        json!({
            "source": {"path": script_path},
            "breakpoints": [{"line": 2}, {"line": 6}]
        }),
    );
    let set_bp = client.expect_response_success("setBreakpoints");
    let breakpoints = set_bp.get("body").and_then(|v| v.get("breakpoints")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    assert_eq!(breakpoints.len(), 2, "expected two breakpoint responses: {set_bp:#}");

    let first_verified = breakpoints.first().and_then(|v| v.get("verified")).and_then(|v| v.as_bool()).unwrap_or(false);
    assert!(first_verified, "first breakpoint should be verified: {set_bp:#}");

    let first_resolved = breakpoints.first().and_then(|v| v.get("line")).and_then(|v| v.as_i64()).unwrap_or_default();
    assert!(first_resolved >= 4, "expected first breakpoint to snap to executable line >= 4, got {first_resolved}");

    let second_resolved = breakpoints.get(1).and_then(|v| v.get("line")).and_then(|v| v.as_i64()).unwrap_or_default();
    assert_eq!(second_resolved, 6, "expected second breakpoint to stay on line 6: {set_bp:#}");

    client.send_request("setExceptionBreakpoints", json!({"filters": []}));
    client.expect_response_success("setExceptionBreakpoints");

    client.send_request("configurationDone", serde_json::Value::Null);
    client.expect_response_success("configurationDone");
    let entry_stop = client.expect_event("stopped");
    let entry_reason = entry_stop.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(entry_reason, "entry");

    client.send_request("continue", json!({"threadId": 1}));
    client.expect_response_success("continue");

    let mut stopped_reason: Option<String> = None;
    let mut terminated_seen = false;
    for _ in 0..12 {
        let msg = client.read_message();
        if msg.get("type") == Some(&serde_json::Value::String("event".to_string())) {
            let event = msg.get("event").and_then(|v| v.as_str()).unwrap_or_default();
            if event == "stopped" {
                stopped_reason = msg.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).map(|v| v.to_string());
                break;
            }
            if event == "terminated" {
                terminated_seen = true;
                break;
            }
        }
    }

    assert!(
        stopped_reason.as_deref() == Some("breakpoint"),
        "expected breakpoint stop after continue; stopped_reason={stopped_reason:?}, terminated_seen={terminated_seen}"
    );

    client.send_request("disconnect", json!({}));
    client.expect_response_success("disconnect");
}

#[test]
fn continue_hits_breakpoint_in_second_entrypoint() {
    let script = TempScript::new(MULTIFUNCTION_IF_STATEMENTS_SCRIPT);
    let script_path = script.path_str();

    let mut client = TestClient::spawn();

    client.send_request(
        "initialize",
        json!({
            "adapterID": "silverscript",
            "pathFormat": "path",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "supportsVariableType": true,
            "supportsVariablePaging": false,
            "supportsRunInTerminalRequest": false
        }),
    );
    client.expect_response_success("initialize");
    client.expect_event("initialized");

    client.send_request(
        "launch",
        json!({
            "scriptPath": script_path,
            "function": "timeout",
            "constructorArgs": ["100", "9"],
            "args": ["9"],
            "stopOnEntry": true
        }),
    );
    client.expect_response_success("launch");

    client.send_request(
        "setBreakpoints",
        json!({
            "source": {"path": script_path},
            "breakpoints": [{"line": 26}]
        }),
    );
    let set_bp = client.expect_response_success("setBreakpoints");
    let breakpoints = set_bp.get("body").and_then(|v| v.get("breakpoints")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    assert_eq!(breakpoints.len(), 1, "expected one breakpoint response: {set_bp:#}");
    let verified = breakpoints.first().and_then(|v| v.get("verified")).and_then(|v| v.as_bool()).unwrap_or(false);
    assert!(verified, "breakpoint should be verified: {set_bp:#}");

    client.send_request("setExceptionBreakpoints", json!({"filters": []}));
    client.expect_response_success("setExceptionBreakpoints");

    client.send_request("configurationDone", serde_json::Value::Null);
    client.expect_response_success("configurationDone");
    let entry_stop = client.expect_event("stopped");
    let entry_reason = entry_stop.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(entry_reason, "entry");

    client.send_request("continue", json!({"threadId": 1}));
    client.expect_response_success("continue");

    let mut stopped_reason: Option<String> = None;
    let mut stopped_line: Option<i64> = None;
    let mut terminated_seen = false;
    for _ in 0..16 {
        let msg = client.read_message();
        if msg.get("type") == Some(&serde_json::Value::String("event".to_string())) {
            let event = msg.get("event").and_then(|v| v.as_str()).unwrap_or_default();
            if event == "stopped" {
                stopped_reason = msg.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).map(|v| v.to_string());

                client.send_request("stackTrace", json!({"threadId": 1}));
                let stack = client.expect_response_success("stackTrace");
                stopped_line = stack
                    .get("body")
                    .and_then(|v| v.get("stackFrames"))
                    .and_then(|v| v.as_array())
                    .and_then(|frames| frames.first())
                    .and_then(|frame| frame.get("line"))
                    .and_then(|v| v.as_i64());
                break;
            }
            if event == "terminated" {
                terminated_seen = true;
                break;
            }
        }
    }

    assert!(
        stopped_reason.as_deref() == Some("breakpoint"),
        "expected breakpoint stop after continue; stopped_reason={stopped_reason:?}, terminated_seen={terminated_seen}"
    );
    assert_eq!(stopped_line, Some(26), "expected stop on line 26 in timeout()");

    client.send_request("disconnect", json!({}));
    client.expect_response_success("disconnect");
}

#[test]
fn continue_with_inline_call_and_callee_breakpoints_does_not_bounce_back_to_call_site() {
    let script = TempScript::new(INLINE_CALL_BOUNCE_SCRIPT);
    let script_path = script.path_str();

    let mut client = TestClient::spawn();

    client.send_request(
        "initialize",
        json!({
            "adapterID": "silverscript",
            "pathFormat": "path",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "supportsVariableType": true,
            "supportsVariablePaging": false,
            "supportsRunInTerminalRequest": false
        }),
    );
    client.expect_response_success("initialize");
    client.expect_event("initialized");

    client.send_request(
        "launch",
        json!({
            "scriptPath": script_path,
            "constructorArgs": [],
            "function": "main",
            "args": ["1", "2"],
            "stopOnEntry": true
        }),
    );
    client.expect_response_success("launch");

    // Request one call-site breakpoint and one callee-body breakpoint.
    client.send_request(
        "setBreakpoints",
        json!({
            "source": {"path": script_path},
            "breakpoints": [{"line": 11}, {"line": 5}]
        }),
    );
    let set_bp = client.expect_response_success("setBreakpoints");
    let breakpoints = set_bp.get("body").and_then(|v| v.get("breakpoints")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    assert_eq!(breakpoints.len(), 2, "expected two breakpoints: {set_bp:#}");
    let call_site_line = breakpoints.first().and_then(|v| v.get("line")).and_then(|v| v.as_i64()).unwrap_or_default();
    let callee_line = breakpoints.get(1).and_then(|v| v.get("line")).and_then(|v| v.as_i64()).unwrap_or_default();

    client.send_request("setExceptionBreakpoints", json!({"filters": []}));
    client.expect_response_success("setExceptionBreakpoints");

    client.send_request("configurationDone", serde_json::Value::Null);
    client.expect_response_success("configurationDone");
    let entry_stop = client.expect_event("stopped");
    let entry_reason = entry_stop.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(entry_reason, "entry");

    let continue_and_capture_line = |client: &mut TestClient| -> Option<i64> {
        client.send_request("continue", json!({"threadId": 1}));
        client.expect_response_success("continue");

        for _ in 0..12 {
            let msg = client.read_message();
            if msg.get("type") == Some(&serde_json::Value::String("event".to_string())) {
                let event = msg.get("event").and_then(|v| v.as_str()).unwrap_or_default();
                if event == "terminated" {
                    return None;
                }
                if event == "stopped" {
                    client.send_request("stackTrace", json!({"threadId": 1}));
                    let stack = client.expect_response_success("stackTrace");
                    return stack
                        .get("body")
                        .and_then(|v| v.get("stackFrames"))
                        .and_then(|v| v.as_array())
                        .and_then(|frames| frames.first())
                        .and_then(|frame| frame.get("line"))
                        .and_then(|v| v.as_i64());
                }
            }
        }
        None
    };

    let first = continue_and_capture_line(&mut client);
    let second = continue_and_capture_line(&mut client);
    let third = continue_and_capture_line(&mut client);

    // Regression check for the user-reported bounce pattern:
    // call-site -> callee -> same call-site.
    let bounced = first == Some(call_site_line) && second == Some(callee_line) && third == Some(call_site_line);
    assert!(
        !bounced,
        "inline breakpoint bounce reproduced: first={first:?}, second={second:?}, third={third:?}, call_site_line={call_site_line}, callee_line={callee_line}"
    );

    client.send_request("disconnect", json!({}));
    client.expect_response_success("disconnect");
}

#[test]
fn continue_after_clearing_breakpoints_with_path_variant_does_not_stop() {
    let script = TempScript::new(INLINE_CALL_BOUNCE_SCRIPT);
    let script_path = script.path_str();
    let variant_path = equivalent_path_variant(&script_path);

    let mut client = TestClient::spawn();

    client.send_request(
        "initialize",
        json!({
            "adapterID": "silverscript",
            "pathFormat": "path",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "supportsVariableType": true,
            "supportsVariablePaging": false,
            "supportsRunInTerminalRequest": false
        }),
    );
    client.expect_response_success("initialize");
    client.expect_event("initialized");

    client.send_request(
        "launch",
        json!({
            "scriptPath": script_path,
            "constructorArgs": [],
            "function": "main",
            "args": ["1", "2"],
            "stopOnEntry": true
        }),
    );
    client.expect_response_success("launch");

    // First set breakpoints on canonical path.
    client.send_request(
        "setBreakpoints",
        json!({
            "source": {"path": script_path},
            "breakpoints": [{"line": 11}, {"line": 5}]
        }),
    );
    let initial_set = client.expect_response_success("setBreakpoints");
    let initial_breakpoints =
        initial_set.get("body").and_then(|v| v.get("breakpoints")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    assert_eq!(initial_breakpoints.len(), 2, "expected two breakpoint responses: {initial_set:#}");

    // Then clear using an equivalent but differently formatted path.
    client.send_request(
        "setBreakpoints",
        json!({
            "source": {"path": variant_path},
            "breakpoints": []
        }),
    );
    client.expect_response_success("setBreakpoints");

    client.send_request("setExceptionBreakpoints", json!({"filters": []}));
    client.expect_response_success("setExceptionBreakpoints");

    client.send_request("configurationDone", serde_json::Value::Null);
    client.expect_response_success("configurationDone");
    let entry_stop = client.expect_event("stopped");
    let entry_reason = entry_stop.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(entry_reason, "entry");

    client.send_request("continue", json!({"threadId": 1}));
    client.expect_response_success("continue");

    let mut stopped_reason: Option<String> = None;
    let mut terminated_seen = false;
    for _ in 0..16 {
        let msg = client.read_message();
        if msg.get("type") == Some(&serde_json::Value::String("event".to_string())) {
            let event = msg.get("event").and_then(|v| v.as_str()).unwrap_or_default();
            if event == "stopped" {
                stopped_reason = msg.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).map(|v| v.to_string());
                break;
            }
            if event == "terminated" {
                terminated_seen = true;
                break;
            }
        }
    }

    assert!(
        stopped_reason.is_none() && terminated_seen,
        "expected termination after clearing breakpoints; stopped_reason={stopped_reason:?}, terminated_seen={terminated_seen}"
    );

    client.send_request("disconnect", json!({}));
    client.expect_response_success("disconnect");
}

#[test]
fn breakpoints_for_launch_source_survive_other_source_updates() {
    let launch_script = TempScript::new(INLINE_CALL_BOUNCE_SCRIPT);
    let launch_path = launch_script.path_str();
    let other_script = TempScript::new(SIMPLE_SCRIPT);
    let other_path = other_script.path_str();

    let mut client = TestClient::spawn();

    client.send_request(
        "initialize",
        json!({
            "adapterID": "silverscript",
            "pathFormat": "path",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "supportsVariableType": true,
            "supportsVariablePaging": false,
            "supportsRunInTerminalRequest": false
        }),
    );
    client.expect_response_success("initialize");
    client.expect_event("initialized");

    client.send_request(
        "launch",
        json!({
            "scriptPath": launch_path,
            "constructorArgs": [],
            "function": "main",
            "args": ["1", "2"],
            "stopOnEntry": true
        }),
    );
    client.expect_response_success("launch");

    // Set one breakpoint in the launched source (call-site line).
    client.send_request(
        "setBreakpoints",
        json!({
            "source": {"path": launch_path},
            "breakpoints": [{"line": 5}]
        }),
    );
    let launch_set = client.expect_response_success("setBreakpoints");
    let launch_bp = launch_set.get("body").and_then(|v| v.get("breakpoints")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    assert_eq!(launch_bp.len(), 1, "expected one launch-source breakpoint response: {launch_set:#}");
    let launch_line = launch_bp.first().and_then(|v| v.get("line")).and_then(|v| v.as_i64()).unwrap_or_default();
    assert!(launch_line > 0, "launch breakpoint should resolve to executable line: {launch_set:#}");

    // Simulate a client sending setBreakpoints for a different source.
    // It should not clear or override launch-source breakpoints.
    client.send_request(
        "setBreakpoints",
        json!({
            "source": {"path": other_path},
            "breakpoints": [{"line": 5}]
        }),
    );
    let other_set = client.expect_response_success("setBreakpoints");
    let other_bp = other_set.get("body").and_then(|v| v.get("breakpoints")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    assert_eq!(other_bp.len(), 1, "expected one foreign-source breakpoint response: {other_set:#}");
    let other_verified = other_bp.first().and_then(|v| v.get("verified")).and_then(|v| v.as_bool()).unwrap_or(true);
    assert!(!other_verified, "foreign-source breakpoint should be unverified: {other_set:#}");

    client.send_request("setExceptionBreakpoints", json!({"filters": []}));
    client.expect_response_success("setExceptionBreakpoints");

    client.send_request("configurationDone", serde_json::Value::Null);
    client.expect_response_success("configurationDone");
    let entry_stop = client.expect_event("stopped");
    let entry_reason = entry_stop.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(entry_reason, "entry");

    client.send_request("continue", json!({"threadId": 1}));
    client.expect_response_success("continue");

    let mut stopped_line: Option<i64> = None;
    let mut terminated_seen = false;
    for _ in 0..16 {
        let msg = client.read_message();
        if msg.get("type") == Some(&serde_json::Value::String("event".to_string())) {
            let event = msg.get("event").and_then(|v| v.as_str()).unwrap_or_default();
            if event == "stopped" {
                let reason = msg.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
                assert_eq!(reason, "breakpoint", "expected breakpoint stop event: {msg:#}");

                client.send_request("stackTrace", json!({"threadId": 1}));
                let stack = client.expect_response_success("stackTrace");
                stopped_line = stack
                    .get("body")
                    .and_then(|v| v.get("stackFrames"))
                    .and_then(|v| v.as_array())
                    .and_then(|frames| frames.first())
                    .and_then(|frame| frame.get("line"))
                    .and_then(|v| v.as_i64());
                break;
            }
            if event == "terminated" {
                terminated_seen = true;
                break;
            }
        }
    }

    assert!(!terminated_seen, "launch-source breakpoint should still be active after foreign-source update");
    assert_eq!(stopped_line, Some(launch_line), "expected stop on launch-source breakpoint line after foreign-source update");

    client.send_request("disconnect", json!({}));
    client.expect_response_success("disconnect");
}
