use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

pub struct TestClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr: BufReader<ChildStderr>,
    seq: i64,
}

impl TestClient {
    pub fn spawn() -> Self {
        let binary = std::env::var("CARGO_BIN_EXE_debugger-dap")
            .or_else(|_| std::env::var("CARGO_BIN_EXE_debugger_dap"))
            .unwrap_or_else(|_| {
                let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                path.push("../../target/debug/debugger-dap");
                path.to_string_lossy().to_string()
            });
        let mut child = Command::new(binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn debugger-dap binary");

        let stdin = child.stdin.take().expect("missing child stdin");
        let stdout = BufReader::new(child.stdout.take().expect("missing child stdout"));
        let stderr = BufReader::new(child.stderr.take().expect("missing child stderr"));

        Self { child, stdin, stdout, stderr, seq: 1 }
    }

    pub fn send_request(&mut self, command: &str, arguments: Value) {
        let message = json!({
            "seq": self.seq,
            "type": "request",
            "command": command,
            "arguments": arguments,
        });
        self.seq += 1;
        self.write_message(&message);
    }

    pub fn read_message(&mut self) -> Value {
        let mut content_length: usize = 0;
        let mut raw_headers: Vec<String> = Vec::new();
        loop {
            let mut line = String::new();
            let bytes = self.stdout.read_line(&mut line).expect("failed to read header line");
            if bytes == 0 {
                let mut stderr = String::new();
                let _ = self.stderr.read_to_string(&mut stderr);
                panic!("adapter closed stdout before sending complete DAP headers; stderr: {stderr}");
            }
            raw_headers.push(line.clone());
            if line.trim().is_empty() {
                if content_length == 0 {
                    continue;
                }
                break;
            }
            if let Some(rest) = line.trim().strip_prefix("Content-Length: ") {
                content_length = rest.trim().parse::<usize>().expect("invalid Content-Length header");
            }
        }

        assert!(content_length > 0, "received DAP message with zero Content-Length; headers: {:?}", raw_headers);

        let mut body = vec![0u8; content_length];
        self.stdout.read_exact(&mut body).expect("failed to read content body");
        serde_json::from_slice::<Value>(&body).expect("invalid JSON payload")
    }

    pub fn expect_response_success(&mut self, command: &str) -> Value {
        loop {
            let msg = self.read_message();
            if msg.get("type") == Some(&Value::String("response".to_string())) {
                let actual = msg.get("command").and_then(|v| v.as_str()).unwrap_or_default();
                if actual == command {
                    let success = msg.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
                    assert!(success, "expected successful response for {command}, got {msg:#}");
                    return msg;
                }
            }
        }
    }

    pub fn expect_event(&mut self, event: &str) -> Value {
        loop {
            let msg = self.read_message();
            if msg.get("type") == Some(&Value::String("event".to_string())) {
                let actual = msg.get("event").and_then(|v| v.as_str()).unwrap_or_default();
                if actual == event {
                    return msg;
                }
            }
        }
    }

    pub fn full_launch_sequence(&mut self, script_path: &str) -> Value {
        self.send_request(
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
        self.expect_response_success("initialize");
        self.expect_event("initialized");

        self.send_request(
            "launch",
            json!({
                "scriptPath": script_path,
                "stopOnEntry": true
            }),
        );
        self.expect_response_success("launch");

        self.send_request("setBreakpoints", json!({"source": {"path": script_path}, "breakpoints": []}));
        self.expect_response_success("setBreakpoints");

        self.send_request("setExceptionBreakpoints", json!({"filters": []}));
        self.expect_response_success("setExceptionBreakpoints");

        self.send_request("configurationDone", Value::Null);
        self.expect_response_success("configurationDone");
        self.expect_event("stopped")
    }

    fn write_message(&mut self, payload: &Value) {
        let encoded = serde_json::to_vec(payload).expect("failed to serialize request");
        let header = format!("Content-Length: {}\r\n\r\n", encoded.len());
        self.stdin.write_all(header.as_bytes()).expect("failed to write header");
        self.stdin.write_all(&encoded).expect("failed to write body");
        self.stdin.flush().expect("failed to flush request");
    }
}

impl Drop for TestClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
