use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::time::SystemTime;

use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use pest::error::LineColLocation;
use rand::{RngCore, thread_rng};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Response, Server, StatusCode};

use silverscript_lang::ast::{ContractAst, SourceSpan, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, CompilerError, compile_contract_ast, function_branch_index};
use silverscript_lang::debug::session::{DebugEngine, DebugSession, OpcodeMeta, StackSnapshot};

mod common;

const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const STYLES_CSS: &str = include_str!("../web/styles.css");

const DEFAULT_TEMPLATE: &str = r#"pragma silverscript ^0.1.0;

contract DebugPoC(int const) {
    function bump(int x) {
        int y = x + 1;
        require(y > 0);
    }

    function check_pair(int leftInput, int rightInput) {
        int left = leftInput + rightInput;
        int right = left * 2;
        require(right >= left);
    }

    entrypoint function main(int a, int b) {
        int seed = a + const;
        check_pair(a, b);
        bump(seed);
        require(seed >= const);
        require(b >= 0);
    }
}
"#;

#[derive(Debug, Clone, Serialize)]
struct ParamInfo {
    name: String,
    type_name: String,
}

#[derive(Debug, Clone, Serialize)]
struct FunctionInfo {
    name: String,
    selector_index: Option<u32>,
    inputs: Vec<ParamInfo>,
}

#[derive(Debug, Clone, Serialize)]
struct OutlineResponse {
    contract_name: String,
    constructor_params: Vec<ParamInfo>,
    functions: Vec<FunctionInfo>,
    without_selector: bool,
}

#[derive(Debug, Deserialize)]
struct OutlineRequest {
    source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunConfig {
    function: Option<String>,
    #[serde(default)]
    ctor_args: Vec<String>,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TraceRequest {
    source: String,
    function: Option<String>,
    #[serde(default)]
    ctor_args: Vec<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    expect_no_selector: bool,
}

#[derive(Debug, Serialize)]
struct SigScriptResponse {
    contract_name: String,
    function_name: String,
    selector_index: Option<i64>,
    sigscript_hex: String,
    sigscript_len: usize,
    without_selector: bool,
}

#[derive(Debug, Serialize)]
struct InitResponse {
    source: String,
    run: RunConfig,
    expect_no_selector: bool,
}

#[derive(Debug, Serialize)]
struct TraceMeta {
    contract_name: String,
    function_name: String,
    selector_index: Option<i64>,
    ctor_args: Vec<String>,
    args: Vec<String>,
    without_selector: bool,
    sigscript_hex: String,
    sigscript_len: usize,
    script_len: usize,
    opcode_count: usize,
    opcode_step_count: usize,
    source_step_count: usize,
    generated_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
struct VarSnapshot {
    name: String,
    origin: String,
    type_name: String,
    value: String,
}

#[derive(Debug, Clone, Serialize)]
struct StepSnapshot {
    pc: usize,
    byte_offset: usize,
    last_opcode: Option<String>,
    mapping: Option<silverscript_lang::debug::DebugMapping>,
    sequence: Option<u32>,
    frame_id: Option<u32>,
    call_depth: Option<u32>,
    call_stack: Vec<String>,
    is_executing: bool,
    stacks: StackSnapshot,
    vars: Vec<VarSnapshot>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct WebTrace {
    meta: TraceMeta,
    source: String,
    opcodes: Vec<OpcodeMeta>,
    // Legacy field kept for older clients. Mirrors opcode_steps.
    steps: Vec<StepSnapshot>,
    opcode_steps: Vec<StepSnapshot>,
    source_steps: Vec<StepSnapshot>,
}

#[derive(Debug, Deserialize)]
struct LegacyCompileRequest {
    source: String,
    function: Option<String>,
    #[serde(default)]
    ctor_args: Vec<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    without_selector: bool,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    span: Option<SourceSpan>,
}

#[derive(Debug)]
struct WebError {
    message: String,
    span: Option<SourceSpan>,
}

impl WebError {
    fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), span: None }
    }

    fn with_span(message: impl Into<String>, span: Option<SourceSpan>) -> Self {
        Self { message: message.into(), span }
    }
}

impl From<CompilerError> for WebError {
    fn from(value: CompilerError) -> Self {
        let span = span_from_compiler_error(&value);
        WebError::with_span(value.to_string(), span)
    }
}

impl std::fmt::Display for WebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for WebError {}

fn span_from_compiler_error(err: &CompilerError) -> Option<SourceSpan> {
    let CompilerError::Parse(parse) = err else {
        return None;
    };
    Some(match &parse.line_col {
        LineColLocation::Pos((line, col)) => {
            SourceSpan { line: *line as u32, col: *col as u32, end_line: *line as u32, end_col: *col as u32 }
        }
        LineColLocation::Span((line, col), (end_line, end_col)) => {
            SourceSpan { line: *line as u32, col: *col as u32, end_line: *end_line as u32, end_col: *end_col as u32 }
        }
    })
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name, value).expect("valid header")
}

fn json<T: Serialize>(status: StatusCode, value: &T) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| br#"{"error":"serialize failed"}"#.to_vec());
    Response::from_data(body).with_status_code(status).with_header(header("Content-Type", "application/json; charset=utf-8"))
}

fn err(status: StatusCode, msg: impl Into<String>, span: Option<SourceSpan>) -> Response<std::io::Cursor<Vec<u8>>> {
    json(status, &ErrorResponse { error: msg.into(), span })
}

fn print_usage() {
    eprintln!(
        "Usage: sil-debug-web [contract.sil] [--no-selector] [--function <name>] [--ctor-arg <value> ...] [--arg <value> ...] [--host <ip>] [--port <n>] [--out <file>] [--no-serve]\n\nExamples:\n  # Serve a single file\n  sil-debug-web path/to/contract.sil --function spend --arg 0x... --arg 0x...\n\nWeb options:\n  --host <ip>    default 127.0.0.1\n  --port <n>     default 7878\n  --out <file>   write trace JSON to file (can be used offline)\n  --no-serve     generate trace then exit\n"
    );
}

#[derive(Debug)]
struct WebArgs {
    script_path: Option<String>,
    expect_no_selector: bool,
    function_name: Option<String>,
    raw_ctor_args: Vec<String>,
    raw_args: Vec<String>,
    host: String,
    port: u16,
    out_path: Option<String>,
    serve: bool,
}

fn parse_args() -> Result<Option<WebArgs>, Box<dyn Error>> {
    let mut script_path: Option<String> = None;
    let mut expect_no_selector = false;
    let mut function_name: Option<String> = None;
    let mut raw_ctor_args: Vec<String> = Vec::new();
    let mut raw_args: Vec<String> = Vec::new();

    let mut host = "127.0.0.1".to_string();
    let mut port: u16 = 7878;
    let mut out_path: Option<String> = None;
    let mut serve = true;

    let mut args = env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--no-selector" => expect_no_selector = true,
            "--function" | "-f" => {
                function_name = args.next();
                if function_name.is_none() {
                    print_usage();
                    return Err("missing function name".into());
                }
            }
            "--ctor-arg" => {
                let value = args.next();
                if value.is_none() {
                    print_usage();
                    return Err("missing --ctor-arg value".into());
                }
                raw_ctor_args.push(value.expect("checked"));
            }
            "--arg" | "-a" => {
                let value = args.next();
                if value.is_none() {
                    print_usage();
                    return Err("missing --arg value".into());
                }
                raw_args.push(value.expect("checked"));
            }
            "--host" => {
                host = args.next().ok_or("missing --host value")?;
            }
            "--port" => {
                let raw = args.next().ok_or("missing --port value")?;
                port = raw.parse::<u16>()?;
            }
            "--out" => {
                out_path = Some(args.next().ok_or("missing --out value")?);
            }
            "--no-serve" => serve = false,
            "-h" | "--help" => {
                print_usage();
                return Ok(None);
            }
            other if other.starts_with('-') => {
                print_usage();
                return Err(format!("unknown option: {other}").into());
            }
            _ => {
                if script_path.is_some() {
                    print_usage();
                    return Err("unexpected extra argument".into());
                }
                script_path = Some(arg);
            }
        }
    }

    Ok(Some(WebArgs { script_path, expect_no_selector, function_name, raw_ctor_args, raw_args, host, port, out_path, serve }))
}

#[derive(Debug, Clone)]
struct ServerState {
    initial_source: String,
    initial_run: RunConfig,
    expect_no_selector: bool,
}

#[derive(Debug)]
struct InitialSource {
    source: String,
}

fn load_initial_source(args: &WebArgs) -> Result<InitialSource, WebError> {
    if let Some(script_path) = &args.script_path {
        let source = fs::read_to_string(script_path).map_err(|e| WebError::new(format!("failed to read {script_path}: {e}")))?;
        return Ok(InitialSource { source });
    }

    Ok(InitialSource { source: DEFAULT_TEMPLATE.to_string() })
}

fn default_raw_value(type_name: &str) -> Option<String> {
    if type_name.strip_suffix("[]").is_some() {
        return Some("[]".to_string());
    }
    match type_name {
        "int" => Some("0".to_string()),
        "bool" => Some("false".to_string()),
        "string" => Some("".to_string()),
        "bytes" => Some("0x".to_string()),
        "byte" => Some("0x00".to_string()),
        "pubkey" => Some(format!("0x{}", "00".repeat(32))),
        "sig" | "datasig" => Some(format!("0x{}", "00".repeat(64))),
        other => {
            if let Some(size) = other.strip_prefix("bytes").and_then(|v| v.parse::<usize>().ok()) {
                Some(format!("0x{}", "00".repeat(size)))
            } else {
                None
            }
        }
    }
}

fn fill_raw_args(expected_types: &[String], raw: Vec<String>) -> Result<Vec<String>, WebError> {
    if raw.len() > expected_types.len() {
        return Err(WebError::new(format!("expects {} arguments, got {}", expected_types.len(), raw.len())));
    }
    let mut out = Vec::with_capacity(expected_types.len());
    for (i, ty) in expected_types.iter().enumerate() {
        let cur = raw.get(i).map(|s| s.trim()).unwrap_or("");
        if cur.is_empty() {
            out.push(default_raw_value(ty).unwrap_or_default());
        } else {
            out.push(cur.to_string());
        }
    }
    Ok(out)
}

fn parse_typed_args(params: &[ParamInfo], raw: &[String], ctx: &str) -> Result<Vec<silverscript_lang::ast::Expr>, WebError> {
    let mut out = Vec::with_capacity(params.len());
    for (i, p) in params.iter().enumerate() {
        let raw_val = raw.get(i).map(String::as_str).unwrap_or("");
        let parsed = common::parse_typed_arg(&p.type_name, raw_val)
            .map_err(|e| WebError::new(format!("invalid {ctx} arg #{i} ({} {}): {e}", p.type_name, p.name)))?;
        out.push(parsed);
    }
    Ok(out)
}

fn outline_from_contract(contract: &ContractAst) -> Result<OutlineResponse, WebError> {
    let ctor = contract.params.iter().map(|p| ParamInfo { name: p.name.clone(), type_name: p.type_name.clone() }).collect::<Vec<_>>();

    let entrypoints = contract.functions.iter().filter(|f| f.entrypoint).collect::<Vec<_>>();
    if entrypoints.is_empty() {
        return Err(WebError::new("contract has no entrypoint functions"));
    }

    let without_selector = entrypoints.len() == 1;
    let functions = entrypoints
        .iter()
        .enumerate()
        .map(|(idx, f)| FunctionInfo {
            name: f.name.clone(),
            selector_index: if without_selector { None } else { Some(idx as u32) },
            inputs: f.params.iter().map(|p| ParamInfo { name: p.name.clone(), type_name: p.type_name.clone() }).collect::<Vec<_>>(),
        })
        .collect::<Vec<_>>();

    Ok(OutlineResponse { contract_name: contract.name.clone(), constructor_params: ctor, functions, without_selector })
}

/// If any sig/datasig arg is a 32-byte secret key, build a dummy transaction,
/// compute the sighash, sign with each secret key, and return the args with
/// real 65-byte Schnorr signatures in place of the 32-byte secret keys.
/// The sighash in Kaspa does not cover the sigscript, so we can compute it
/// with an empty sigscript and the resulting signatures remain valid.
fn auto_sign_args(fn_params: &[ParamInfo], raw_args: &[String], script: &[u8]) -> Result<Vec<String>, WebError> {
    // Collect secret keys for sig/datasig params that are exactly 32 bytes.
    let secret_keys: Vec<Option<SecretKey>> = fn_params
        .iter()
        .enumerate()
        .map(|(i, p)| {
            if p.type_name != "sig" && p.type_name != "datasig" {
                return None;
            }
            let val = raw_args.get(i).map(String::as_str).unwrap_or("");
            let hex_str = val.strip_prefix("0x").unwrap_or(val);
            hex::decode(hex_str).ok().and_then(|b| if b.len() == 32 { SecretKey::from_slice(&b).ok() } else { None })
        })
        .collect();

    if !secret_keys.iter().any(Option::is_some) {
        return Ok(raw_args.to_vec());
    }

    // Build a dummy transaction to derive the sighash.
    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([9u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 8,
    };
    let output = TransactionOutput { value: 5000, script_public_key: ScriptPublicKey::new(0, script.into()), covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output], 0, Default::default(), 0, vec![]);
    let utxo = UtxoEntry::new(5000, ScriptPublicKey::new(0, script.into()), 0, tx.is_coinbase(), None);
    let reused = SigHashReusedValuesUnsync::new();
    let populated = PopulatedTransaction::new(&tx, vec![utxo]);
    let sig_hash = calc_schnorr_signature_hash(&populated, 0, SIG_HASH_ALL, &reused);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice())
        .map_err(|e| WebError::new(format!("sighash error: {e}")))?;

    let secp = Secp256k1::new();
    let mut signed = raw_args.to_vec();
    for (i, sk) in secret_keys.iter().enumerate() {
        if let Some(sk) = sk {
            let kp = Keypair::from_secret_key(&secp, sk);
            let schnorr_sig = kp.sign_schnorr(msg);
            let mut signature = Vec::with_capacity(65);
            signature.extend_from_slice(schnorr_sig.as_ref());
            signature.push(SIG_HASH_ALL.to_u8());
            signed[i] = format!("0x{}", hex::encode(&signature));
        }
    }
    Ok(signed)
}

/// Shared logic: parse contract, compile, resolve function, fill args, auto-sign.
struct ResolvedContract {
    compiled: silverscript_lang::compiler::CompiledContract,
    selected_name: String,
    fn_params: Vec<ParamInfo>,
    raw_ctor_args: Vec<String>,
    signed_args: Vec<String>,
}

fn resolve_and_sign(
    source: &str,
    function_name: Option<String>,
    raw_ctor_args: Vec<String>,
    raw_args: Vec<String>,
    expect_no_selector: bool,
    compile_opts: CompileOptions,
) -> Result<ResolvedContract, WebError> {
    let contract = parse_contract_ast(source).map_err(WebError::from)?;
    let outline = outline_from_contract(&contract)?;
    if expect_no_selector && !outline.without_selector {
        return Err(WebError::new("--no-selector requires exactly one entrypoint function"));
    }

    let ctor_types = outline.constructor_params.iter().map(|p| p.type_name.clone()).collect::<Vec<_>>();
    let raw_ctor_args = fill_raw_args(&ctor_types, raw_ctor_args).map_err(|e| WebError::new(format!("constructor {}", e.message)))?;
    let ctor_exprs = parse_typed_args(&outline.constructor_params, &raw_ctor_args, "constructor")?;

    let compiled = compile_contract_ast(&contract, &ctor_exprs, compile_opts).map_err(WebError::from)?;

    let default_name =
        compiled.abi.first().map(|entry| entry.name.clone()).ok_or_else(|| WebError::new("contract has no functions"))?;
    let selected_name = function_name.filter(|s| !s.trim().is_empty()).unwrap_or(default_name);
    let entry = compiled
        .abi
        .iter()
        .find(|entry| entry.name == selected_name)
        .ok_or_else(|| WebError::new(format!("function '{selected_name}' not found")))?;

    let fn_params =
        entry.inputs.iter().map(|p| ParamInfo { name: p.name.clone(), type_name: p.type_name.clone() }).collect::<Vec<_>>();
    let fn_types = fn_params.iter().map(|p| p.type_name.clone()).collect::<Vec<_>>();
    let raw_args = fill_raw_args(&fn_types, raw_args).map_err(|e| WebError::new(format!("function {}", e.message)))?;

    let signed_args = auto_sign_args(&fn_params, &raw_args, &compiled.script)?;

    Ok(ResolvedContract { compiled, selected_name, fn_params, raw_ctor_args, signed_args })
}

fn build_sigscript_from_source(
    source: &str,
    function_name: Option<String>,
    raw_ctor_args: Vec<String>,
    raw_args: Vec<String>,
    expect_no_selector: bool,
) -> Result<SigScriptResponse, WebError> {
    let r = resolve_and_sign(source, function_name, raw_ctor_args, raw_args, expect_no_selector, CompileOptions::default())?;
    let typed_args = parse_typed_args(&r.fn_params, &r.signed_args, "function")?;
    let sigscript = r.compiled.build_sig_script(&r.selected_name, typed_args).map_err(|e| WebError::new(e.to_string()))?;
    let selector_index = if r.compiled.without_selector {
        None
    } else {
        Some(function_branch_index(&r.compiled.ast, &r.selected_name).map_err(WebError::from)?)
    };

    Ok(SigScriptResponse {
        contract_name: r.compiled.contract_name,
        function_name: r.selected_name,
        selector_index,
        sigscript_len: sigscript.len(),
        sigscript_hex: hex::encode(sigscript),
        without_selector: r.compiled.without_selector,
    })
}

fn build_trace_from_source(
    source: String,
    function_name: Option<String>,
    raw_ctor_args: Vec<String>,
    raw_args: Vec<String>,
    expect_no_selector: bool,
) -> Result<WebTrace, WebError> {
    let opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let r = resolve_and_sign(&source, function_name, raw_ctor_args, raw_args, expect_no_selector, opts)?;
    let typed_args = parse_typed_args(&r.fn_params, &r.signed_args, "function")?;
    let sigscript = r.compiled.build_sig_script(&r.selected_name, typed_args).map_err(|e| WebError::new(e.to_string()))?;
    let sigscript_hex = hex::encode(&sigscript);
    let selector_index = if r.compiled.without_selector {
        None
    } else {
        Some(function_branch_index(&r.compiled.ast, &r.selected_name).map_err(WebError::from)?)
    };

    // Build the transaction for script execution.
    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([9u8; 32]), index: 0 },
        signature_script: sigscript.clone(),
        sequence: 0,
        sig_op_count: 8,
    };
    let output = TransactionOutput {
        value: 5000,
        script_public_key: ScriptPublicKey::new(0, r.compiled.script.clone().into()),
        covenant: None,
    };
    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(5000, ScriptPublicKey::new(0, r.compiled.script.clone().into()), 0, tx.is_coinbase(), None);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);

    let engine: DebugEngine<'_> = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &input,
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );

    let mut session = DebugSession::full(&sigscript, &r.compiled.script, &source, r.compiled.debug_info.clone(), engine)
        .map_err(|e| WebError::new(e.to_string()))?;

    let opcodes = session.opcode_metas();
    let mut opcode_steps = Vec::with_capacity(opcodes.len() + 1);
    opcode_steps.push(snapshot(&session, None, false));
    loop {
        match session.step_opcode() {
            Ok(Some(_)) => opcode_steps.push(snapshot(&session, None, false)),
            Ok(None) => break,
            Err(err) => {
                opcode_steps.push(snapshot(&session, Some(err.to_string()), false));
                break;
            }
        }
    }
    drop(session);

    let engine: DebugEngine<'_> = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &input,
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );
    let mut source_session = DebugSession::full(&sigscript, &r.compiled.script, &source, r.compiled.debug_info.clone(), engine)
        .map_err(|e| WebError::new(e.to_string()))?;

    let mut source_steps = Vec::new();
    match source_session.run_to_first_executed_statement() {
        Ok(()) => {
            source_steps.push(snapshot(&source_session, None, true));
            loop {
                match source_session.step_into() {
                    Ok(Some(_)) => source_steps.push(snapshot(&source_session, None, true)),
                    Ok(None) => {
                        let terminal = snapshot(&source_session, None, true);
                        let should_push_terminal = source_steps.last().map_or(true, |last| {
                            last.pc != terminal.pc
                                || last.byte_offset != terminal.byte_offset
                                || last.is_executing != terminal.is_executing
                                || last.sequence != terminal.sequence
                                || last.frame_id != terminal.frame_id
                        });
                        if should_push_terminal {
                            source_steps.push(terminal);
                        }
                        break;
                    }
                    Err(err) => {
                        source_steps.push(snapshot(&source_session, Some(err.to_string()), true));
                        break;
                    }
                }
            }
        }
        Err(err) => source_steps.push(snapshot(&source_session, Some(err.to_string()), true)),
    }

    let generated_at_unix_ms = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);

    Ok(WebTrace {
        meta: TraceMeta {
            contract_name: r.compiled.contract_name,
            function_name: r.selected_name,
            selector_index,
            ctor_args: r.raw_ctor_args,
            args: r.signed_args,
            without_selector: r.compiled.without_selector,
            sigscript_hex,
            sigscript_len: sigscript.len(),
            script_len: r.compiled.script.len(),
            opcode_count: opcodes.len(),
            opcode_step_count: opcode_steps.len(),
            source_step_count: source_steps.len(),
            generated_at_unix_ms,
        },
        source,
        opcodes,
        steps: opcode_steps.clone(),
        opcode_steps,
        source_steps,
    })
}

fn snapshot(session: &DebugSession<'_>, error: Option<String>, include_call_stack: bool) -> StepSnapshot {
    let state = session.state();
    let vars = match state.mapping.as_ref() {
        Some(mapping) => session.list_variables_at_sequence(mapping.sequence, mapping.frame_id),
        None => session.list_variables(),
    };
    let vars = match vars {
        Ok(list) => list
            .into_iter()
            .map(|v| VarSnapshot {
                name: v.name,
                origin: v.origin.label().to_string(),
                type_name: v.type_name.clone(),
                value: session.format_value(&v.type_name, &v.value),
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    let sequence = state.mapping.as_ref().map(|mapping| mapping.sequence);
    let frame_id = state.mapping.as_ref().map(|mapping| mapping.frame_id);
    let call_depth = state.mapping.as_ref().map(|mapping| mapping.call_depth);
    let call_stack = if include_call_stack { session.call_stack() } else { Vec::new() };
    StepSnapshot {
        pc: state.pc,
        byte_offset: session.current_byte_offset(),
        last_opcode: state.opcode,
        mapping: state.mapping,
        sequence,
        frame_id,
        call_depth,
        call_stack,
        is_executing: session.is_executing(),
        stacks: session.stacks_snapshot(),
        vars,
        error,
    }
}

fn read_body(req: &mut tiny_http::Request) -> Result<String, WebError> {
    let mut body = String::new();
    req.as_reader().read_to_string(&mut body).map_err(|_| WebError::new("failed to read request body"))?;
    Ok(body)
}

fn serve(host: &str, port: u16, state: ServerState) -> Result<(), Box<dyn Error>> {
    let server = Server::http(format!("{host}:{port}"))
        .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, format!("cannot bind {host}:{port}: {e}")))?;
    eprintln!("sil-debug-web listening on http://{host}:{port}/");

    let h_html = header("Content-Type", "text/html; charset=utf-8");
    let h_js = header("Content-Type", "application/javascript; charset=utf-8");
    let h_css = header("Content-Type", "text/css; charset=utf-8");

    for mut req in server.incoming_requests() {
        let url = req.url().to_string();
        let method = req.method().clone();

        let resp = 'resp: {
            match (method, url.as_str()) {
                (Method::Get, "/") => Response::from_string(INDEX_HTML).with_header(h_html.clone()),
                (Method::Get, "/app.js") => Response::from_string(APP_JS).with_header(h_js.clone()),
                (Method::Get, "/styles.css") => Response::from_string(STYLES_CSS).with_header(h_css.clone()),

                (Method::Get, "/api/init") => {
                    let init = InitResponse {
                        source: state.initial_source.clone(),
                        run: state.initial_run.clone(),
                        expect_no_selector: state.expect_no_selector,
                    };
                    json(StatusCode(200), &init)
                }

                (Method::Post, "/api/outline") => {
                    let body = match read_body(&mut req) {
                        Ok(body) => body,
                        Err(e) => break 'resp err(StatusCode(400), e.message, e.span),
                    };
                    match serde_json::from_str::<OutlineRequest>(&body) {
                        Ok(r) => match parse_contract_ast(&r.source) {
                            Ok(contract) => match outline_from_contract(&contract) {
                                Ok(outline) => json(StatusCode(200), &outline),
                                Err(e) => err(StatusCode(400), e.message, e.span),
                            },
                            Err(e) => err(StatusCode(400), e.to_string(), span_from_compiler_error(&e)),
                        },
                        Err(e) => err(StatusCode(400), format!("invalid JSON: {e}"), None),
                    }
                }

                (Method::Post, "/api/sigscript") => {
                    let body = match read_body(&mut req) {
                        Ok(body) => body,
                        Err(e) => break 'resp err(StatusCode(400), e.message, e.span),
                    };
                    match serde_json::from_str::<TraceRequest>(&body) {
                        Ok(r) => match build_sigscript_from_source(&r.source, r.function, r.ctor_args, r.args, r.expect_no_selector) {
                            Ok(out) => json(StatusCode(200), &out),
                            Err(e) => err(StatusCode(400), e.message, e.span),
                        },
                        Err(e) => err(StatusCode(400), format!("invalid JSON: {e}"), None),
                    }
                }

                (Method::Post, "/api/trace") => {
                    let body = match read_body(&mut req) {
                        Ok(body) => body,
                        Err(e) => break 'resp err(StatusCode(400), e.message, e.span),
                    };
                    match serde_json::from_str::<TraceRequest>(&body) {
                        Ok(r) => match build_trace_from_source(r.source, r.function, r.ctor_args, r.args, r.expect_no_selector) {
                            Ok(trace) => json(StatusCode(200), &trace),
                            Err(e) => err(StatusCode(400), e.message, e.span),
                        },
                        Err(e) => err(StatusCode(400), format!("invalid JSON: {e}"), None),
                    }
                }

                (Method::Get, "/api/keygen") => {
                    let secp = Secp256k1::new();
                    let mut rng = thread_rng();
                    let mut sk_bytes = [0u8; 32];
                    let keypair = loop {
                        rng.fill_bytes(&mut sk_bytes);
                        if let Ok(secret_key) = SecretKey::from_slice(&sk_bytes) {
                            break Keypair::from_secret_key(&secp, &secret_key);
                        }
                    };
                    let xonly_pk = keypair.x_only_public_key().0.serialize();
                    let pkh = blake2b_simd::Params::new().hash_length(32).to_state().update(&xonly_pk).finalize();
                    #[derive(Serialize)]
                    struct KeygenResponse {
                        pubkey: String,
                        sig: String,
                        secret_key: String,
                        pkh: String,
                    }
                    json(
                        StatusCode(200),
                        &KeygenResponse {
                            pubkey: format!("0x{}", hex::encode(xonly_pk)),
                            sig: format!("0x{}", hex::encode(&sk_bytes)),
                            secret_key: format!("0x{}", hex::encode(&sk_bytes)),
                            pkh: format!("0x{}", hex::encode(pkh.as_bytes())),
                        },
                    )
                }

                // Legacy routes used by older UIs.
                (Method::Get, "/trace") => match build_trace_from_source(
                    state.initial_source.clone(),
                    state.initial_run.function.clone(),
                    state.initial_run.ctor_args.clone(),
                    state.initial_run.args.clone(),
                    state.expect_no_selector,
                ) {
                    Ok(trace) => json(StatusCode(200), &trace),
                    Err(e) => err(StatusCode(400), e.message, e.span),
                },

                (Method::Post, "/compile") => {
                    let body = match read_body(&mut req) {
                        Ok(body) => body,
                        Err(e) => break 'resp err(StatusCode(400), e.message, e.span),
                    };
                    match serde_json::from_str::<LegacyCompileRequest>(&body) {
                        Ok(r) => match build_trace_from_source(r.source, r.function, r.ctor_args, r.args, r.without_selector) {
                            Ok(trace) => json(StatusCode(200), &trace),
                            Err(e) => err(StatusCode(400), e.message, e.span),
                        },
                        Err(e) => err(StatusCode(400), format!("invalid JSON: {e}"), None),
                    }
                }

                (_, _) => Response::from_string("not found").with_status_code(StatusCode(404)),
            }
        };

        let _ = req.respond(resp);
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let Some(args) = parse_args()? else { return Ok(()) };

    let initial = load_initial_source(&args)?;
    let state = ServerState {
        initial_source: initial.source.clone(),
        initial_run: RunConfig {
            function: args.function_name.clone(),
            ctor_args: args.raw_ctor_args.clone(),
            args: args.raw_args.clone(),
        },
        expect_no_selector: args.expect_no_selector,
    };

    // Offline trace generation
    if args.out_path.is_some() || !args.serve {
        let trace = build_trace_from_source(
            initial.source,
            args.function_name.clone(),
            args.raw_ctor_args.clone(),
            args.raw_args.clone(),
            args.expect_no_selector,
        )?;
        let trace_json = serde_json::to_string(&trace)?;
        if let Some(out) = &args.out_path {
            fs::write(out, &trace_json)?;
            eprintln!("Wrote trace JSON to {}", out);
        }
        if !args.serve {
            return Ok(());
        }
    }

    serve(&args.host, args.port, state)?;
    Ok(())
}
