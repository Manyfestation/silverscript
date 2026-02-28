use std::path::{Path, PathBuf};

use dap::requests::LaunchRequestArguments;
use debugger_session::test_runner::values_to_args;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchConfig {
    pub script_path: Option<String>,
    pub test_file: Option<String>,
    pub test_name: Option<String>,
    pub function: Option<String>,
    #[serde(default)]
    pub constructor_args: Vec<Value>,
    #[serde(default)]
    pub args: Vec<Value>,
    #[serde(default)]
    #[allow(dead_code)]
    pub without_selector: bool,
    #[serde(default = "default_stop_on_entry")]
    pub stop_on_entry: bool,
}

fn default_stop_on_entry() -> bool {
    true
}

impl LaunchConfig {
    pub fn from_launch_args(args: &LaunchRequestArguments) -> Result<Self, String> {
        let value = args.additional_data.clone().unwrap_or(Value::Null);
        let config: Self = serde_json::from_value(value).map_err(|err| format!("invalid launch config: {err}"))?;

        if config.script_path.is_none() && config.test_file.is_none() {
            return Err("launch config must include 'scriptPath' or 'testFile'".to_string());
        }

        if config.test_file.is_some() && config.test_name.is_none() {
            return Err("launch config with 'testFile' must include 'testName'".to_string());
        }

        Ok(config)
    }

    pub fn resolve_script_path(&self, workspace_root: Option<&Path>) -> Result<PathBuf, String> {
        let raw = self.script_path.as_deref().ok_or_else(|| "scriptPath is required for contract launch".to_string())?;
        canonicalize_with_workspace(raw, workspace_root)
    }

    pub fn resolve_test_file_path(&self, workspace_root: Option<&Path>) -> Result<PathBuf, String> {
        let raw = self.test_file.as_deref().ok_or_else(|| "testFile is required for test launch".to_string())?;
        canonicalize_with_workspace(raw, workspace_root)
    }

    pub fn constructor_args_as_strings(&self) -> Result<Vec<String>, String> {
        values_to_args(&self.constructor_args)
    }

    pub fn args_as_strings(&self) -> Result<Vec<String>, String> {
        values_to_args(&self.args)
    }
}

fn canonicalize_with_workspace(raw: &str, workspace_root: Option<&Path>) -> Result<PathBuf, String> {
    let candidate = PathBuf::from(raw);
    let resolved = if candidate.is_absolute() {
        candidate
    } else if let Some(root) = workspace_root {
        root.join(candidate)
    } else {
        std::env::current_dir().map_err(|err| format!("failed to resolve current_dir: {err}"))?.join(candidate)
    };

    std::fs::canonicalize(&resolved).map_err(|err| format!("failed to canonicalize '{}': {err}", resolved.display()))
}
