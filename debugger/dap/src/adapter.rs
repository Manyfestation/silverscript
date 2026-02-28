use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use dap::events::{Event, OutputEventBody, StoppedEventBody};
use dap::prelude::{Command, Request, Response, ResponseBody};
use dap::responses::{
    ContinueResponse, ScopesResponse, SetBreakpointsResponse, StackTraceResponse, ThreadsResponse, VariablesResponse,
};
use dap::types::{
    Breakpoint, Capabilities, OutputEventCategory, Scope, ScopePresentationhint, Source, StackFrame, StoppedEventReason, Thread,
    Variable,
};
use debugger_session::args::{parse_call_args, parse_ctor_args, parse_hex_bytes};
use debugger_session::format_failure_report;
use debugger_session::session::{DebugEngine, DebugSession, ShadowTxContext, VariableOrigin};
use debugger_session::test_runner::{TestTxScenarioResolved, TestTxInputScenarioResolved, TestTxOutputScenarioResolved, resolve_contract_test};
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineCtx, EngineFlags, pay_to_script_hash_script};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use silverscript_lang::ast::{ContractAst, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};

use crate::launch_config::LaunchConfig;
use crate::refs::{RefAllocator, RefTarget, ScopeKind};

const MAIN_THREAD_ID: i64 = 1;

pub struct AdapterResult {
    pub response: Response,
    pub events: Vec<Event>,
    pub should_exit: bool,
}

pub struct DapAdapter {
    runtime: Option<Runtime>,
    refs: RefAllocator,
    frame_sequence: i64,
    configured: bool,
}

struct Runtime {
    session: DebugSession<'static, 'static>,
    source_path: PathBuf,
    source_name: String,
    stop_on_entry: bool,
    breakpoints_by_source: HashMap<String, HashSet<u32>>,
    frame_map: Vec<FrameMeta>,
}

#[derive(Clone)]
struct FrameMeta {
    frame_id: i64,
    sequence: u32,
    frame_token: u32,
}

impl DapAdapter {
    pub fn new() -> Self {
        Self { runtime: None, refs: RefAllocator::new(), frame_sequence: 1, configured: false }
    }

    pub fn handle_request(&mut self, req: Request) -> AdapterResult {
        match self.handle_request_inner(req.clone()) {
            Ok(result) => result,
            Err(err) => {
                AdapterResult { response: req.error(&format!("internal adapter error: {err}")), events: vec![], should_exit: false }
            }
        }
    }

    fn handle_request_inner(&mut self, req: Request) -> Result<AdapterResult, String> {
        match req.command.clone() {
            Command::Initialize(_) => {
                let capabilities = Capabilities {
                    supports_configuration_done_request: Some(true),
                    supports_step_in_targets_request: Some(false),
                    supports_function_breakpoints: Some(false),
                    supports_conditional_breakpoints: Some(false),
                    support_terminate_debuggee: Some(true),
                    supports_loaded_sources_request: Some(false),
                    supports_evaluate_for_hovers: Some(false),
                    ..Default::default()
                };
                Ok(AdapterResult {
                    response: req.success(ResponseBody::Initialize(capabilities)),
                    events: vec![Event::Initialized],
                    should_exit: false,
                })
            }
            Command::Launch(args) => {
                let launch = match LaunchConfig::from_launch_args(&args) {
                    Ok(cfg) => cfg,
                    Err(err) => {
                        return Ok(AdapterResult {
                            response: req.error(&err),
                            events: vec![self.output_stderr(err)],
                            should_exit: false,
                        });
                    }
                };

                match build_runtime(launch) {
                    Ok(runtime) => {
                        self.runtime = Some(runtime);
                        self.configured = false;
                        Ok(AdapterResult { response: req.success(ResponseBody::Launch), events: vec![], should_exit: false })
                    }
                    Err(err) => {
                        Ok(AdapterResult { response: req.error(&err), events: vec![self.output_stderr(err)], should_exit: false })
                    }
                }
            }
            Command::SetBreakpoints(args) => {
                let runtime = self.runtime.as_mut().ok_or_else(|| "setBreakpoints before launch".to_string())?;
                let requested_source_path =
                    args.source.path.as_deref().map(PathBuf::from).unwrap_or_else(|| runtime.source_path.clone());
                let source_key = canonical_source_key(&requested_source_path);

                if let Some(existing) = runtime.breakpoints_by_source.remove(&source_key) {
                    for line in existing {
                        runtime.session.clear_breakpoint(line);
                    }
                }
                let requested_lines: Vec<i64> = if let Some(requested) = args.breakpoints {
                    Some(requested.into_iter().map(|source_bp| source_bp.line).collect::<Vec<_>>())
                } else {
                    #[allow(deprecated)]
                    args.lines
                }
                .unwrap_or_default();

                if !runtime.stop_on_entry {
                    runtime.breakpoints_by_source.insert(source_key, HashSet::new());
                    let breakpoints = requested_lines
                        .into_iter()
                        .map(|line| Breakpoint { verified: false, line: Some(line), ..Default::default() })
                        .collect();
                    return Ok(AdapterResult {
                        response: req.success(ResponseBody::SetBreakpoints(SetBreakpointsResponse { breakpoints })),
                        events: vec![],
                        should_exit: false,
                    });
                }

                let runtime_source_key = canonical_source_key(&runtime.source_path);
                if source_key != runtime_source_key {
                    // This adapter session executes one script file. Keep breakpoints
                    // from other files isolated and report them as unverified.
                    runtime.breakpoints_by_source.insert(source_key, HashSet::new());
                    let breakpoints = requested_lines
                        .into_iter()
                        .map(|line| Breakpoint { verified: false, line: Some(line), ..Default::default() })
                        .collect();
                    return Ok(AdapterResult {
                        response: req.success(ResponseBody::SetBreakpoints(SetBreakpointsResponse { breakpoints })),
                        events: vec![],
                        should_exit: false,
                    });
                }

                let mut breakpoints = Vec::new();
                let mut resolved_for_source = HashSet::new();
                for line_value in requested_lines {
                    if line_value <= 0 {
                        breakpoints.push(Breakpoint { verified: false, line: Some(line_value), ..Default::default() });
                        continue;
                    }
                    let line = line_value as u32;
                    let resolved = runtime.session.add_breakpoint_resolved(line);
                    let verified = resolved.is_some();
                    if let Some(actual_line) = resolved {
                        resolved_for_source.insert(actual_line);
                    }
                    breakpoints.push(Breakpoint { verified, line: Some(resolved.unwrap_or(line) as i64), ..Default::default() });
                }

                runtime.breakpoints_by_source.insert(source_key, resolved_for_source);

                Ok(AdapterResult {
                    response: req.success(ResponseBody::SetBreakpoints(SetBreakpointsResponse { breakpoints })),
                    events: vec![],
                    should_exit: false,
                })
            }
            Command::SetExceptionBreakpoints(_) => Ok(AdapterResult {
                response: req.success(ResponseBody::SetExceptionBreakpoints(Default::default())),
                events: vec![],
                should_exit: false,
            }),
            Command::ConfigurationDone => {
                let runtime = self.runtime.as_mut().ok_or_else(|| "configurationDone before launch".to_string())?;
                self.configured = true;

                runtime.session.run_to_first_executed_statement().map_err(|err| format!("failed to start session: {err}"))?;

                let events = if runtime.stop_on_entry {
                    vec![self.make_stopped_event(StoppedEventReason::Entry, None)]
                } else {
                    match runtime.session.continue_to_breakpoint() {
                        Ok(Some(_)) => vec![self.make_stopped_event(StoppedEventReason::Breakpoint, None)],
                        Ok(None) => vec![Event::Terminated(None)],
                        Err(err) => {
                            let report = runtime.session.build_failure_report(&err);
                            let formatted =
                                format_failure_report(&report, &|type_name, value| runtime.session.format_value(type_name, value));
                            vec![self.output_stderr(formatted), Event::Terminated(None)]
                        }
                    }
                };

                Ok(AdapterResult { response: req.success(ResponseBody::ConfigurationDone), events, should_exit: false })
            }
            Command::Threads => Ok(AdapterResult {
                response: req.success(ResponseBody::Threads(ThreadsResponse {
                    threads: vec![Thread { id: MAIN_THREAD_ID, name: "main".to_string() }],
                })),
                events: vec![],
                should_exit: false,
            }),
            Command::StackTrace(_) => {
                let (span, location, source, current_function_name, call_stack) = {
                    let runtime = self.runtime.as_ref().ok_or_else(|| "stackTrace before launch".to_string())?;
                    let span = runtime.session.current_span();
                    let location = runtime.session.current_location();
                    let source = Source {
                        name: Some(runtime.source_name.clone()),
                        path: Some(runtime.source_path.to_string_lossy().to_string()),
                        ..Default::default()
                    };
                    let current_function_name =
                        runtime.session.current_function_name().map(ToOwned::to_owned).unwrap_or_else(|| "<entry>".to_string());
                    let call_stack = runtime.session.call_stack_with_spans();
                    (span, location, source, current_function_name, call_stack)
                };

                let mut frames = Vec::new();
                let mut frame_map = Vec::new();

                let current_line = span.map(|s| s.line as i64).unwrap_or(1);
                let current_col = span.map(|s| s.col as i64).unwrap_or(1);

                let frame_id = self.next_frame_id();
                frames.push(StackFrame {
                    id: frame_id,
                    name: current_function_name,
                    source: Some(source.clone()),
                    line: current_line,
                    column: current_col,
                    ..Default::default()
                });
                frame_map.push(FrameMeta {
                    frame_id,
                    sequence: location.as_ref().map(|m| m.sequence).unwrap_or(0),
                    frame_token: location.as_ref().map(|m| m.frame_id).unwrap_or(0),
                });

                for entry in call_stack.into_iter().rev() {
                    let id = self.next_frame_id();
                    let frame_line = entry.call_site_span.map(|s| s.line as i64).unwrap_or(current_line);
                    let frame_col = entry.call_site_span.map(|s| s.col as i64).unwrap_or(current_col);
                    frames.push(StackFrame {
                        id,
                        name: entry.callee_name,
                        source: Some(source.clone()),
                        line: frame_line,
                        column: frame_col,
                        ..Default::default()
                    });
                    frame_map.push(FrameMeta {
                        frame_id: id,
                        sequence: entry.sequence,
                        frame_token: entry.frame_id,
                    });
                }

                if let Some(runtime_mut) = self.runtime.as_mut() {
                    runtime_mut.frame_map = frame_map;
                }

                Ok(AdapterResult {
                    response: req.success(ResponseBody::StackTrace(StackTraceResponse {
                        total_frames: Some(frames.len() as i64),
                        stack_frames: frames,
                    })),
                    events: vec![],
                    should_exit: false,
                })
            }
            Command::Scopes(args) => {
                let runtime = self.runtime.as_ref().ok_or_else(|| "scopes before launch".to_string())?;
                let frame_meta = runtime
                    .frame_map
                    .iter()
                    .find(|frame| frame.frame_id == args.frame_id)
                    .cloned()
                    .unwrap_or(FrameMeta { frame_id: args.frame_id, sequence: 0, frame_token: 0 });

                let locals_ref = self.refs.alloc(RefTarget::Scope(ScopeKind::Locals));
                let stack_ref = self.refs.alloc(RefTarget::Scope(ScopeKind::Stack));
                let constants_ref = self.refs.alloc(RefTarget::Scope(ScopeKind::Constants));
                let locals =
                    runtime.session.list_variables_at_sequence(frame_meta.sequence, frame_meta.frame_token).unwrap_or_default();
                let locals_count =
                    locals.iter().filter(|item| item.origin == VariableOrigin::Local || item.origin == VariableOrigin::Param).count();
                let constants_count = locals.iter().filter(|item| item.is_constant).count();

                let scopes = vec![
                    Scope {
                        name: "Locals".to_string(),
                        presentation_hint: Some(ScopePresentationhint::Locals),
                        variables_reference: locals_ref,
                        named_variables: Some(locals_count as i64),
                        expensive: false,
                        ..Default::default()
                    },
                    Scope {
                        name: "Stack".to_string(),
                        presentation_hint: Some(ScopePresentationhint::Registers),
                        variables_reference: stack_ref,
                        expensive: false,
                        ..Default::default()
                    },
                    Scope {
                        name: "Constants".to_string(),
                        presentation_hint: Some(ScopePresentationhint::Arguments),
                        variables_reference: constants_ref,
                        named_variables: Some(constants_count as i64),
                        expensive: false,
                        ..Default::default()
                    },
                ];

                Ok(AdapterResult {
                    response: req.success(ResponseBody::Scopes(ScopesResponse { scopes })),
                    events: vec![],
                    should_exit: false,
                })
            }
            Command::Variables(args) => {
                let runtime = self.runtime.as_ref().ok_or_else(|| "variables before launch".to_string())?;
                let target = self
                    .refs
                    .get(args.variables_reference)
                    .cloned()
                    .ok_or_else(|| format!("unknown variablesReference {}", args.variables_reference))?;

                let variables = match target {
                    RefTarget::Scope(ScopeKind::Locals) => {
                        let vars = runtime.session.list_variables().map_err(|err| format!("locals unavailable: {err}"))?;
                        vars.into_iter()
                            .filter(|item| item.origin == VariableOrigin::Local || item.origin == VariableOrigin::Param)
                            .map(|item| Variable {
                                name: item.name.clone(),
                                value: runtime.session.format_value(&item.type_name, &item.value),
                                type_field: Some(item.type_name),
                                evaluate_name: Some(item.name),
                                variables_reference: 0,
                                ..Default::default()
                            })
                            .collect::<Vec<_>>()
                    }
                    RefTarget::Scope(ScopeKind::Constants) => {
                        let vars = runtime.session.list_variables().map_err(|err| format!("constants unavailable: {err}"))?;
                        vars.into_iter()
                            .filter(|item| item.is_constant)
                            .map(|item| Variable {
                                name: item.name,
                                value: runtime.session.format_value(&item.type_name, &item.value),
                                type_field: Some(item.type_name),
                                variables_reference: 0,
                                ..Default::default()
                            })
                            .collect::<Vec<_>>()
                    }
                    RefTarget::Scope(ScopeKind::Stack) => {
                        let snapshot = runtime.session.stacks_snapshot();
                        let mut out = Vec::new();
                        for (index, item) in snapshot.dstack.iter().enumerate() {
                            out.push(Variable {
                                name: format!("dstack[{index}]"),
                                value: format!("0x{item}"),
                                variables_reference: 0,
                                ..Default::default()
                            });
                        }
                        for (index, item) in snapshot.astack.iter().enumerate() {
                            out.push(Variable {
                                name: format!("astack[{index}]"),
                                value: format!("0x{item}"),
                                variables_reference: 0,
                                ..Default::default()
                            });
                        }
                        out
                    }
                };

                Ok(AdapterResult {
                    response: req.success(ResponseBody::Variables(VariablesResponse { variables })),
                    events: vec![],
                    should_exit: false,
                })
            }
            Command::Next(_) => self.handle_step(req, StepKind::Next, |session| session.step_over()),
            Command::StepIn(_) => self.handle_step(req, StepKind::StepIn, |session| session.step_into()),
            Command::StepOut(_) => self.handle_step(req, StepKind::StepOut, |session| session.step_out()),
            Command::Continue(_) => {
                let runtime = self.runtime.as_mut().ok_or_else(|| "continue before launch".to_string())?;
                let stop_on_entry = runtime.stop_on_entry;
                let mut events = Vec::new();
                match runtime.session.continue_to_breakpoint() {
                    Ok(Some(_)) => events.push(self.make_stopped_event(StoppedEventReason::Breakpoint, None)),
                    Ok(None) => events.push(Event::Terminated(None)),
                    Err(err) => {
                        let report = runtime.session.build_failure_report(&err);
                        let formatted =
                            format_failure_report(&report, &|type_name, value| runtime.session.format_value(type_name, value));
                        events.push(self.output_stderr(formatted.clone()));
                        if stop_on_entry {
                            events.push(self.make_stopped_event(StoppedEventReason::Exception, Some(formatted)));
                        } else {
                            events.push(Event::Terminated(None));
                        }
                    }
                }
                Ok(AdapterResult {
                    response: req.success(ResponseBody::Continue(ContinueResponse { all_threads_continued: Some(true) })),
                    events,
                    should_exit: false,
                })
            }
            Command::Disconnect(_) => {
                self.runtime = None;
                Ok(AdapterResult { response: req.success(ResponseBody::Disconnect), events: vec![], should_exit: true })
            }
            _ => Ok(AdapterResult { response: req.error("unsupported request"), events: vec![], should_exit: false }),
        }
    }

    fn handle_step(
        &mut self,
        req: Request,
        step_kind: StepKind,
        mut step_fn: impl FnMut(
            &mut DebugSession<'static, 'static>,
        ) -> Result<Option<debugger_session::session::SessionState>, kaspa_txscript_errors::TxScriptError>,
    ) -> Result<AdapterResult, String> {
        if !self.configured {
            return Ok(AdapterResult {
                response: req.error("cannot step before configurationDone"),
                events: vec![],
                should_exit: false,
            });
        }

        let runtime = self.runtime.as_mut().ok_or_else(|| "step request before launch".to_string())?;
        let mut events = Vec::new();
        let before_location = current_location_key(&runtime.session);
        let mut step_result = step_fn(&mut runtime.session);

        let mut guard = 0usize;
        while matches!(step_result, Ok(Some(_))) && guard < 32 {
            let after_location = current_location_key(&runtime.session);
            if after_location != before_location {
                break;
            }
            step_result = step_fn(&mut runtime.session);
            guard += 1;
        }

        match step_result {
            Ok(Some(_)) => events.push(self.make_stopped_event(StoppedEventReason::Step, None)),
            Ok(None) => events.push(Event::Terminated(None)),
            Err(err) => {
                let report = runtime.session.build_failure_report(&err);
                let formatted = format_failure_report(&report, &|type_name, value| runtime.session.format_value(type_name, value));
                events.push(self.output_stderr(formatted.clone()));
                events.push(self.make_stopped_event(StoppedEventReason::Exception, Some(formatted)));
            }
        }

        let body = match step_kind {
            StepKind::Next => ResponseBody::Next,
            StepKind::StepIn => ResponseBody::StepIn,
            StepKind::StepOut => ResponseBody::StepOut,
        };

        Ok(AdapterResult { response: req.success(body), events, should_exit: false })
    }

    fn make_stopped_event(&mut self, reason: StoppedEventReason, text: Option<String>) -> Event {
        self.refs.reset();
        Event::Stopped(StoppedEventBody {
            reason,
            description: None,
            thread_id: Some(MAIN_THREAD_ID),
            preserve_focus_hint: None,
            text,
            all_threads_stopped: Some(true),
            hit_breakpoint_ids: None,
        })
    }

    fn next_frame_id(&mut self) -> i64 {
        let id = self.frame_sequence;
        self.frame_sequence += 1;
        id
    }

    fn output_stderr(&self, msg: impl Into<String>) -> Event {
        Event::Output(OutputEventBody {
            category: Some(OutputEventCategory::Stderr),
            output: format!("{}\n", msg.into()),
            ..Default::default()
        })
    }
}

enum StepKind {
    Next,
    StepIn,
    StepOut,
}

fn current_location_key(session: &DebugSession<'static, 'static>) -> Option<u32> {
    session.current_span().map(|span| span.line)
}

fn canonical_source_key(path: &Path) -> String {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()).to_string_lossy().to_string()
}

/// Detect 32-byte secret keys in sig/datasig args. Returns indices + keys for deferred signing.
fn detect_secret_keys(input_types: &[String], raw_args: &[String]) -> Vec<Option<SecretKey>> {
    input_types
        .iter()
        .enumerate()
        .map(|(i, type_name)| {
            if type_name != "sig" && type_name != "datasig" {
                return None;
            }
            let val = raw_args.get(i).map(String::as_str).unwrap_or("");
            let bytes = parse_hex_bytes(val).ok()?;
            if bytes.len() == 32 { SecretKey::from_slice(&bytes).ok() } else { None }
        })
        .collect()
}

/// Sign secret-key args against a real populated tx sighash, replacing them with 65-byte Schnorr sigs.
fn sign_args_with_tx(
    secret_keys: &[Option<SecretKey>],
    raw_args: &mut [String],
    populated: &PopulatedTransaction<'_>,
    active_input_index: usize,
) -> Result<(), String> {
    if !secret_keys.iter().any(Option::is_some) {
        return Ok(());
    }
    let reused = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(populated, active_input_index, SIG_HASH_ALL, &reused);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice())
        .map_err(|e| format!("sighash error: {e}"))?;

    let secp = Secp256k1::new();
    for (i, sk) in secret_keys.iter().enumerate() {
        if let Some(sk) = sk {
            let kp = Keypair::from_secret_key(&secp, sk);
            let schnorr_sig = kp.sign_schnorr(msg);
            let mut signature = Vec::with_capacity(65);
            signature.extend_from_slice(schnorr_sig.as_ref());
            signature.push(SIG_HASH_ALL.to_u8());
            raw_args[i] = format!("0x{}", signature.iter().map(|b| format!("{b:02x}")).collect::<String>());
        }
    }
    Ok(())
}

fn build_runtime(config: LaunchConfig) -> Result<Runtime, String> {
    let stop_on_entry = config.stop_on_entry;

    let (script_path, selected_function, raw_ctor_args, mut raw_args, tx_scenario) = if config.test_file.is_some() {
        let test_name = config.test_name.clone().ok_or_else(|| "launch config with 'testFile' must include 'testName'".to_string())?;
        let test_file_path = config.resolve_test_file_path(None)?;
        let script_override = if config.script_path.is_some() { Some(config.resolve_script_path(None)?) } else { None };
        let resolved = resolve_contract_test(&test_file_path, &test_name, script_override.as_deref())?;

        (resolved.script_path, Some(resolved.test.function), resolved.test.constructor_args, resolved.test.args, resolved.test.tx)
    } else {
        let inline_tx = config.resolve_inline_tx()?;
        (
            config.resolve_script_path(None)?,
            config.function.clone(),
            config.constructor_args_as_strings()?,
            config.args_as_strings()?,
            inline_tx,
        )
    };

    let source_owned =
        fs::read_to_string(&script_path).map_err(|err| format!("failed to read source '{}': {err}", script_path.display()))?;
    let source: &'static str = Box::leak(source_owned.into_boxed_str());

    let parsed_contract = parse_contract_ast(source).map_err(|err| format!("parse error: {err}"))?;
    let ctor_args = parse_ctor_args(&parsed_contract, &raw_ctor_args)?;

    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(source, &ctor_args, compile_opts).map_err(|err| format!("compile error: {err}"))?;
    let mut ctor_script_cache = HashMap::<Vec<String>, Vec<u8>>::new();
    ctor_script_cache.insert(raw_ctor_args.clone(), compiled.script.clone());

    let selected_name = if let Some(function) = selected_function {
        function
    } else {
        match compiled.abi.as_slice() {
            [] => return Err("contract has no functions".to_string()),
            [entry] => entry.name.clone(),
            entries => {
                let names = entries.iter().map(|entry| entry.name.as_str()).collect::<Vec<_>>().join(", ");
                return Err(format!("launch config must include 'function' for multi-entrypoint contract (available: {names})"));
            }
        }
    };

    let entry = compiled
        .abi
        .iter()
        .find(|entry| entry.name == selected_name)
        .ok_or_else(|| format!("function '{}' not found", selected_name))?;

    let input_types = entry.inputs.iter().map(|input| input.type_name.clone()).collect::<Vec<_>>();
    let secret_keys = detect_secret_keys(&input_types, &raw_args);

    // Phase 1: build sigscript with placeholder sigs (zeroed 65 bytes) for any secret-key args.
    // This lets us construct the full tx to compute the real sighash.
    let placeholder_args: Vec<String> = raw_args
        .iter()
        .enumerate()
        .map(|(i, arg)| {
            if secret_keys[i].is_some() {
                format!("0x{}", "00".repeat(65))
            } else {
                arg.clone()
            }
        })
        .collect();
    let placeholder_typed = parse_call_args(&input_types, &placeholder_args)?;
    let placeholder_sigscript = compiled
        .build_sig_script(&selected_name, placeholder_typed)
        .map_err(|err| format!("failed to build sigscript: {err}"))?;

    let flags = EngineFlags { covenants_enabled: true };
    let tx = tx_scenario.unwrap_or_else(|| TestTxScenarioResolved {
        version: 1,
        lock_time: 0,
        active_input_index: 0,
        inputs: vec![TestTxInputScenarioResolved {
            prev_txid: None,
            prev_index: 0,
            sequence: 0,
            sig_op_count: 100,
            utxo_value: 5000,
            covenant_id: None,
            constructor_args: None,
            signature_script_hex: None,
            utxo_script_hex: None,
        }],
        outputs: vec![TestTxOutputScenarioResolved {
            value: 5000,
            covenant_id: None,
            authorizing_input: None,
            constructor_args: None,
            script_hex: None,
            p2pk_pubkey: None,
        }],
    });

    // Phase 2: if we have secret keys, build the real tx to get the sighash, sign, rebuild sigscript.
    let sigscript = if secret_keys.iter().any(Option::is_some) {
        let temp_tx = build_unsigned_tx(source, &parsed_contract, &raw_ctor_args, &mut ctor_script_cache, &placeholder_sigscript, &tx)?;
        sign_args_with_tx(&secret_keys, &mut raw_args, &temp_tx, tx.active_input_index)?;
        let typed_args = parse_call_args(&input_types, &raw_args)?;
        compiled.build_sig_script(&selected_name, typed_args).map_err(|err| format!("failed to build sigscript: {err}"))?
    } else {
        let typed_args = parse_call_args(&input_types, &raw_args)?;
        compiled.build_sig_script(&selected_name, typed_args).map_err(|err| format!("failed to build sigscript: {err}"))?
    };

    let session = build_session_with_tx(
        source,
        &parsed_contract,
        &raw_ctor_args,
        &mut ctor_script_cache,
        &sigscript,
        &compiled.script,
        compiled.debug_info.clone(),
        tx,
        flags,
    )?;

    let source_name = script_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| script_path.to_string_lossy().to_string());

    Ok(Runtime {
        session,
        source_path: script_path,
        source_name,
        stop_on_entry,
        breakpoints_by_source: HashMap::new(),
        frame_map: Vec::new(),
    })
}

/// Build a temporary PopulatedTransaction for sighash computation (auto-signing).
/// Uses the same tx construction logic as build_session_with_tx but returns just the populated tx.
fn build_unsigned_tx(
    source: &str,
    parsed_contract: &ContractAst<'_>,
    raw_ctor_args: &[String],
    ctor_script_cache: &mut HashMap<Vec<String>, Vec<u8>>,
    sigscript: &[u8],
    tx: &TestTxScenarioResolved,
) -> Result<PopulatedTransaction<'static>, String> {
    let mut tx_inputs = Vec::with_capacity(tx.inputs.len());
    let mut utxo_specs = Vec::with_capacity(tx.inputs.len());
    for (input_idx, input) in tx.inputs.iter().enumerate() {
        let mut default_prev_txid = [0u8; 32];
        default_prev_txid.fill(input_idx as u8);
        let prev_txid = if let Some(raw_txid) = input.prev_txid.as_deref() {
            parse_txid32(raw_txid)?
        } else {
            TransactionId::from_bytes(default_prev_txid)
        };

        let input_ctor_raw = input.constructor_args.clone().unwrap_or_else(|| raw_ctor_args.to_vec());
        let redeem_script = if input.utxo_script_hex.is_none() {
            Some(compile_script_for_ctor_args(source, parsed_contract, &input_ctor_raw, ctor_script_cache)?)
        } else {
            None
        };

        let signature_script = if let Some(raw_sig) = input.signature_script_hex.as_deref() {
            parse_hex_bytes(raw_sig).map_err(|err| format!("invalid signature_script_hex: {err}"))?
        } else if input_idx == tx.active_input_index {
            if let Some(redeem) = redeem_script.as_ref() { combine_action_and_redeem(sigscript, redeem)? } else { sigscript.to_vec() }
        } else if let Some(redeem) = redeem_script.as_ref() {
            sigscript_push_script(redeem)
        } else {
            vec![]
        };

        let utxo_spk = if let Some(raw_script) = input.utxo_script_hex.as_deref() {
            ScriptPublicKey::new(0, parse_hex_bytes(raw_script).map_err(|err| format!("invalid input.utxo_script_hex: {err}"))?.into())
        } else {
            let redeem = redeem_script.as_ref().ok_or_else(|| "internal error: missing redeem script".to_string())?;
            pay_to_script_hash_script(redeem)
        };

        let covenant_id = if let Some(raw) = input.covenant_id.as_deref() { Some(parse_hash32(raw)?) } else { None };

        tx_inputs.push(TransactionInput {
            previous_outpoint: TransactionOutpoint { transaction_id: prev_txid, index: input.prev_index },
            signature_script,
            sequence: input.sequence,
            sig_op_count: input.sig_op_count,
        });
        utxo_specs.push((input.utxo_value, utxo_spk, covenant_id));
    }

    let mut tx_outputs = Vec::with_capacity(tx.outputs.len());
    for output in &tx.outputs {
        let script_public_key = if let Some(raw_script) = output.script_hex.as_deref() {
            ScriptPublicKey::new(0, parse_hex_bytes(raw_script).map_err(|err| format!("invalid output.script_hex: {err}"))?.into())
        } else if let Some(raw_pubkey) = output.p2pk_pubkey.as_deref() {
            let pubkey_bytes = parse_hex_bytes(raw_pubkey).map_err(|err| format!("invalid output.p2pk_pubkey: {err}"))?;
            ScriptPublicKey::new(0, build_p2pk_script(&pubkey_bytes).into())
        } else {
            let output_ctor_raw = output.constructor_args.clone().unwrap_or_else(|| raw_ctor_args.to_vec());
            let output_script = compile_script_for_ctor_args(source, parsed_contract, &output_ctor_raw, ctor_script_cache)?;
            pay_to_script_hash_script(&output_script)
        };

        let covenant = if let Some(raw) = output.covenant_id.as_deref() {
            Some(CovenantBinding {
                authorizing_input: output.authorizing_input.unwrap_or(tx.active_input_index as u16),
                covenant_id: parse_hash32(raw)?,
            })
        } else {
            None
        };

        tx_outputs.push(TransactionOutput { value: output.value, script_public_key, covenant });
    }

    let tx_obj = Box::leak(Box::new(Transaction::new(tx.version, tx_inputs, tx_outputs, tx.lock_time, Default::default(), 0, vec![])));
    let utxos = utxo_specs
        .into_iter()
        .map(|(value, spk, covenant_id)| UtxoEntry::new(value, spk, 0, tx_obj.is_coinbase(), covenant_id))
        .collect::<Vec<_>>();
    Ok(PopulatedTransaction::new(tx_obj, utxos))
}

fn build_session_with_tx(
    source: &'static str,
    parsed_contract: &ContractAst<'_>,
    raw_ctor_args: &[String],
    ctor_script_cache: &mut HashMap<Vec<String>, Vec<u8>>,
    sigscript: &[u8],
    lockscript: &[u8],
    debug_info: Option<silverscript_lang::debug_info::DebugInfo<'static>>,
    tx: TestTxScenarioResolved,
    flags: EngineFlags,
) -> Result<DebugSession<'static, 'static>, String> {
    if tx.inputs.is_empty() {
        return Err("test tx.inputs must contain at least one input".to_string());
    }
    if tx.active_input_index >= tx.inputs.len() {
        return Err(format!("test tx.active_input_index {} out of range for {} inputs", tx.active_input_index, tx.inputs.len()));
    }

    let mut tx_inputs = Vec::with_capacity(tx.inputs.len());
    let mut utxo_specs = Vec::with_capacity(tx.inputs.len());
    for (input_idx, input) in tx.inputs.iter().enumerate() {
        let mut default_prev_txid = [0u8; 32];
        default_prev_txid.fill(input_idx as u8);
        let prev_txid = if let Some(raw_txid) = input.prev_txid.as_deref() {
            parse_txid32(raw_txid)?
        } else {
            TransactionId::from_bytes(default_prev_txid)
        };

        let input_ctor_raw = input.constructor_args.clone().unwrap_or_else(|| raw_ctor_args.to_vec());
        let redeem_script = if input.utxo_script_hex.is_none() {
            Some(compile_script_for_ctor_args(source, parsed_contract, &input_ctor_raw, ctor_script_cache)?)
        } else {
            None
        };

        let signature_script = if let Some(raw_sig) = input.signature_script_hex.as_deref() {
            parse_hex_bytes(raw_sig).map_err(|err| format!("invalid signature_script_hex: {err}"))?
        } else if input_idx == tx.active_input_index {
            if let Some(redeem) = redeem_script.as_ref() { combine_action_and_redeem(sigscript, redeem)? } else { sigscript.to_vec() }
        } else if let Some(redeem) = redeem_script.as_ref() {
            sigscript_push_script(redeem)
        } else {
            vec![]
        };

        let utxo_spk = if let Some(raw_script) = input.utxo_script_hex.as_deref() {
            ScriptPublicKey::new(0, parse_hex_bytes(raw_script).map_err(|err| format!("invalid input.utxo_script_hex: {err}"))?.into())
        } else {
            let redeem = redeem_script
                .as_ref()
                .ok_or_else(|| "internal error: missing redeem script for tx input without utxo_script_hex".to_string())?;
            pay_to_script_hash_script(redeem)
        };

        let covenant_id = if let Some(raw) = input.covenant_id.as_deref() { Some(parse_hash32(raw)?) } else { None };

        tx_inputs.push(TransactionInput {
            previous_outpoint: TransactionOutpoint { transaction_id: prev_txid, index: input.prev_index },
            signature_script,
            sequence: input.sequence,
            sig_op_count: input.sig_op_count,
        });
        utxo_specs.push((input.utxo_value, utxo_spk, covenant_id));
    }

    let mut tx_outputs = Vec::with_capacity(tx.outputs.len());
    for output in &tx.outputs {
        let script_public_key = if let Some(raw_script) = output.script_hex.as_deref() {
            ScriptPublicKey::new(0, parse_hex_bytes(raw_script).map_err(|err| format!("invalid output.script_hex: {err}"))?.into())
        } else if let Some(raw_pubkey) = output.p2pk_pubkey.as_deref() {
            let pubkey_bytes = parse_hex_bytes(raw_pubkey).map_err(|err| format!("invalid output.p2pk_pubkey: {err}"))?;
            let p2pk_script = build_p2pk_script(&pubkey_bytes);
            ScriptPublicKey::new(0, p2pk_script.into())
        } else {
            let output_ctor_raw = output.constructor_args.clone().unwrap_or_else(|| raw_ctor_args.to_vec());
            let output_script = compile_script_for_ctor_args(source, parsed_contract, &output_ctor_raw, ctor_script_cache)?;
            pay_to_script_hash_script(&output_script)
        };

        let covenant = if let Some(raw) = output.covenant_id.as_deref() {
            Some(CovenantBinding {
                authorizing_input: output.authorizing_input.unwrap_or(tx.active_input_index as u16),
                covenant_id: parse_hash32(raw)?,
            })
        } else {
            None
        };

        tx_outputs.push(TransactionOutput { value: output.value, script_public_key, covenant });
    }

    let tx_obj = Box::leak(Box::new(Transaction::new(tx.version, tx_inputs, tx_outputs, tx.lock_time, Default::default(), 0, vec![])));

    let utxos = utxo_specs
        .into_iter()
        .map(|(value, spk, covenant_id)| UtxoEntry::new(value, spk, 0, tx_obj.is_coinbase(), covenant_id))
        .collect::<Vec<_>>();
    let populated_tx = Box::leak(Box::new(PopulatedTransaction::new(tx_obj, utxos)));
    let cov_ctx = Box::leak(Box::new(
        CovenantsContext::from_tx(populated_tx).map_err(|err| format!("failed to build covenant context: {err}"))?,
    ));
    let cache = Box::leak(Box::new(Cache::new(10_000)));
    let reused: &'static SigHashReusedValuesUnsync = Box::leak(Box::new(SigHashReusedValuesUnsync::new()));
    let ctx = EngineCtx::new(cache).with_reused(reused).with_covenants_ctx(cov_ctx);
    let active_input =
        tx_obj.inputs.get(tx.active_input_index).ok_or_else(|| format!("missing tx input at index {}", tx.active_input_index))?;
    let active_utxo =
        populated_tx.utxo(tx.active_input_index).ok_or_else(|| format!("missing utxo entry for input {}", tx.active_input_index))?;
    let engine = DebugEngine::from_transaction_input(populated_tx, active_input, tx.active_input_index, active_utxo, ctx, flags);
    let shadow_tx_context = ShadowTxContext {
        tx: populated_tx,
        input: active_input,
        input_index: tx.active_input_index,
        utxo_entry: active_utxo,
        covenants_ctx: cov_ctx,
    };

    DebugSession::full(sigscript, lockscript, source, debug_info, engine)
        .map_err(|err| format!("failed to create debug session: {err}"))
        .map(|session| session.with_shadow_tx_context(shadow_tx_context))
}

fn compile_script_for_ctor_args(
    source: &str,
    parsed_contract: &ContractAst<'_>,
    raw_ctor_args: &[String],
    cache: &mut HashMap<Vec<String>, Vec<u8>>,
) -> Result<Vec<u8>, String> {
    if let Some(script) = cache.get(raw_ctor_args) {
        return Ok(script.clone());
    }

    let ctor_args = parse_ctor_args(parsed_contract, raw_ctor_args)?;
    let compiled = compile_contract(source, &ctor_args, CompileOptions::default()).map_err(|err| format!("compile error: {err}"))?;
    cache.insert(raw_ctor_args.to_vec(), compiled.script.clone());
    Ok(compiled.script)
}

fn parse_hash32(raw: &str) -> Result<Hash, String> {
    let bytes = parse_hex_bytes(raw).map_err(|err| format!("invalid hash '{raw}': {err}"))?;
    if bytes.len() != 32 {
        return Err(format!("hash expects 32 bytes, got {}", bytes.len()));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(Hash::from_bytes(array))
}

fn parse_txid32(raw: &str) -> Result<TransactionId, String> {
    let bytes = parse_hex_bytes(raw).map_err(|err| format!("invalid txid '{raw}': {err}"))?;
    if bytes.len() != 32 {
        return Err(format!("txid expects 32 bytes, got {}", bytes.len()));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(TransactionId::from_bytes(array))
}

fn sigscript_push_script(script: &[u8]) -> Vec<u8> {
    ScriptBuilder::new().add_data(script).expect("push script data").drain()
}

fn combine_action_and_redeem(action: &[u8], redeem_script: &[u8]) -> Result<Vec<u8>, String> {
    let mut builder = ScriptBuilder::new();
    builder.add_ops(action).map_err(|err| format!("failed to append action script: {err}"))?;
    builder.add_data(redeem_script).map_err(|err| format!("failed to append redeem script: {err}"))?;
    Ok(builder.drain())
}

fn build_p2pk_script(pubkey: &[u8]) -> Vec<u8> {
    ScriptBuilder::new()
        .add_data(pubkey)
        .unwrap()
        .add_op(kaspa_txscript::opcodes::codes::OpCheckSig)
        .unwrap()
        .drain()
}
