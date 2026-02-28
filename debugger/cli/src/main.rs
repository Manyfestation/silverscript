use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineCtx, EngineFlags, pay_to_script_hash_script};
use serde::Deserialize;

use debugger_session::args::{parse_call_args, parse_ctor_args, parse_hex_bytes};
use debugger_session::format_failure_report;
use debugger_session::session::{DebugEngine, DebugSession, ShadowTxContext};
use silverscript_lang::ast::{ContractAst, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};

const PROMPT: &str = "(sdb) ";

#[derive(Debug, Parser)]
#[command(name = "cli-debugger", about = "SilverScript debugger")]
struct CliArgs {
    script_path: Option<String>,
    #[arg(long = "scenario")]
    scenario_path: Option<String>,
    #[arg(long = "no-selector")]
    without_selector: bool,
    #[arg(long = "function", short = 'f')]
    function_name: Option<String>,
    #[arg(long = "ctor-arg")]
    raw_ctor_args: Vec<String>,
    #[arg(long = "arg", short = 'a')]
    raw_args: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DebugScenario {
    #[serde(default)]
    script_path: Option<String>,
    #[serde(default)]
    constructor_args: Vec<String>,
    #[serde(default)]
    function: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    active_input_index: usize,
    tx: TxScenario,
}

#[derive(Debug, Deserialize)]
struct TxScenario {
    #[serde(default = "default_tx_version")]
    version: u16,
    #[serde(default)]
    lock_time: u64,
    inputs: Vec<TxInputScenario>,
    outputs: Vec<TxOutputScenario>,
}

#[derive(Debug, Deserialize)]
struct TxInputScenario {
    #[serde(default)]
    prev_txid: Option<String>,
    #[serde(default)]
    prev_index: u32,
    #[serde(default)]
    sequence: u64,
    #[serde(default)]
    sig_op_count: u8,
    utxo_value: u64,
    #[serde(default)]
    covenant_id: Option<String>,
    #[serde(default)]
    constructor_args: Option<Vec<String>>,
    #[serde(default)]
    signature_script_hex: Option<String>,
    #[serde(default)]
    utxo_script_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TxOutputScenario {
    value: u64,
    #[serde(default)]
    covenant_id: Option<String>,
    #[serde(default)]
    authorizing_input: Option<u16>,
    #[serde(default)]
    constructor_args: Option<Vec<String>>,
    #[serde(default)]
    script_hex: Option<String>,
}

fn default_tx_version() -> u16 {
    1
}

fn compile_script_for_ctor_args(
    source: &str,
    parsed_contract: &ContractAst<'_>,
    raw_ctor_args: &[String],
    cache: &mut HashMap<Vec<String>, Vec<u8>>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(script) = cache.get(raw_ctor_args) {
        return Ok(script.clone());
    }
    let ctor_args = parse_ctor_args(parsed_contract, raw_ctor_args)?;
    let compiled = compile_contract(source, &ctor_args, CompileOptions::default())?;
    cache.insert(raw_ctor_args.to_vec(), compiled.script.clone());
    Ok(compiled.script)
}

fn parse_hash32(raw: &str) -> Result<Hash, Box<dyn std::error::Error>> {
    let bytes = parse_hex_bytes(raw)?;
    if bytes.len() != 32 {
        return Err(format!("hash expects 32 bytes, got {}", bytes.len()).into());
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(Hash::from_bytes(array))
}

fn parse_txid32(raw: &str) -> Result<TransactionId, Box<dyn std::error::Error>> {
    let bytes = parse_hex_bytes(raw)?;
    if bytes.len() != 32 {
        return Err(format!("txid expects 32 bytes, got {}", bytes.len()).into());
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(TransactionId::from_bytes(array))
}

fn sigscript_push_script(script: &[u8]) -> Vec<u8> {
    ScriptBuilder::new().add_data(script).expect("push script data").drain()
}

fn combine_action_and_redeem(action: &[u8], redeem_script: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut builder = ScriptBuilder::new();
    builder.add_ops(action)?;
    builder.add_data(redeem_script)?;
    Ok(builder.drain())
}

fn resolve_source_path(
    cli_script_path: Option<&str>,
    scenario_path: Option<&Path>,
    scenario_script_path: Option<&str>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = cli_script_path {
        return Ok(PathBuf::from(path));
    }
    if let Some(path) = scenario_script_path {
        let candidate = PathBuf::from(path);
        if candidate.is_absolute() {
            return Ok(candidate);
        }
        if let Some(base) = scenario_path.and_then(Path::parent) {
            return Ok(base.join(candidate));
        }
        return Ok(candidate);
    }
    Err("missing script path: pass positional SCRIPT_PATH or scenario.script_path".into())
}

fn show_stack(session: &DebugSession<'_, '_>) {
    println!("Stack:");
    let stack = session.stack();
    for (i, item) in stack.iter().enumerate().rev() {
        println!("[{i}] {item}");
    }
}

fn show_source_context(session: &DebugSession<'_, '_>) {
    let Some(context) = session.source_context() else {
        println!("No source context available.");
        return;
    };

    for line in context.lines {
        let marker = if line.is_active { "→" } else { " " };
        println!("{marker} {:>4} | {}", line.line, line.text);
    }
}

fn show_vars(session: &DebugSession<'_, '_>) {
    match session.list_variables() {
        Ok(variables) => {
            if variables.is_empty() {
                println!("No variables in scope.");
            } else {
                for var in variables {
                    let constant_suffix = if var.is_constant { " (const)" } else { "" };
                    println!(
                        "{}{} ({}) = {}",
                        var.name,
                        constant_suffix,
                        var.type_name,
                        session.format_value(&var.type_name, &var.value)
                    );
                }
            }
        }
        Err(err) => println!("ERROR: {err}"),
    }
}

fn show_step_view(session: &DebugSession<'_, '_>) {
    show_source_context(session);
    show_vars(session);
}

fn print_failure(session: &DebugSession<'_, '_>, err: kaspa_txscript_errors::TxScriptError) {
    let report = session.build_failure_report(&err);
    let formatted = format_failure_report(&report, &|type_name, value| session.format_value(type_name, value));
    eprintln!("{formatted}");
}

fn run_repl(session: &mut DebugSession<'_, '_>) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    loop {
        print!("{PROMPT}");
        io::stdout().flush().ok();

        let mut cmd = String::new();
        if stdin.lock().read_line(&mut cmd).is_err() {
            println!("Failed to read input.");
            continue;
        }

        let cmd = cmd.trim();
        if cmd.is_empty() || cmd == "n" || cmd == "next" {
            match session.step_over() {
                Ok(Some(_)) => show_step_view(session),
                Ok(None) => {
                    println!("Done.");
                    break;
                }
                Err(err) => {
                    print_failure(session, err);
                    break;
                }
            }
            continue;
        }

        let mut parts = cmd.split_whitespace();
        match parts.next().unwrap_or("") {
            "step" | "s" => match session.step_into() {
                Ok(Some(_)) => show_step_view(session),
                Ok(None) => {
                    println!("Done.");
                    break;
                }
                Err(err) => {
                    print_failure(session, err);
                    break;
                }
            },
            "si" => match session.step_opcode() {
                Ok(Some(_)) => show_step_view(session),
                Ok(None) => {
                    println!("Done.");
                    break;
                }
                Err(err) => {
                    print_failure(session, err);
                    break;
                }
            },
            "finish" | "out" => match session.step_out() {
                Ok(Some(_)) => show_step_view(session),
                Ok(None) => {
                    println!("Done.");
                    break;
                }
                Err(err) => {
                    print_failure(session, err);
                    break;
                }
            },
            "c" | "continue" => match session.continue_to_breakpoint() {
                Ok(Some(_)) => show_step_view(session),
                Ok(None) => {
                    println!("Done.");
                    break;
                }
                Err(err) => {
                    print_failure(session, err);
                    break;
                }
            },
            "b" | "break" => {
                if let Some(arg) = parts.next() {
                    match arg.parse::<u32>() {
                        Ok(line) => {
                            if session.add_breakpoint(line) {
                                println!("Breakpoint set at line {line}");
                            } else {
                                println!("Warning: no statement at line {line}, breakpoint not set");
                            }
                        }
                        Err(_) => println!("Invalid line number."),
                    }
                } else {
                    let lines = session.breakpoints();
                    if lines.is_empty() {
                        println!("No breakpoints set.");
                    } else {
                        println!("Breakpoints: {}", lines.iter().map(|line| line.to_string()).collect::<Vec<_>>().join(", "));
                    }
                }
            }
            "l" | "list" => show_source_context(session),
            "vars" => show_vars(session),
            "print" | "p" => {
                if let Some(name) = parts.next() {
                    match session.variable_by_name(name) {
                        Ok(var) => {
                            let constant_suffix = if var.is_constant { " (const)" } else { "" };
                            println!(
                                "{}{} ({}) = {}",
                                var.name,
                                constant_suffix,
                                var.type_name,
                                session.format_value(&var.type_name, &var.value)
                            );
                        }
                        Err(err) => println!("ERROR: {err}"),
                    }
                } else {
                    println!("Usage: print <name>");
                }
            }
            "stack" => show_stack(session),
            "q" | "quit" => break,
            "help" | "h" | "?" => {
                println!(
                    "Commands: next/over (n), step/into (s), step opcode (si), finish/out, continue (c), break (b <line>), list (l), vars, print <name>, stack, quit (q)"
                )
            }
            _ => println!(
                "Commands: next/over (n), step/into (s), step opcode (si), finish/out, continue (c), break (b <line>), list (l), vars, print <name>, stack, quit (q)"
            ),
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = CliArgs::parse();
    let scenario_path = cli.scenario_path.as_deref().map(PathBuf::from);
    let scenario = if let Some(path) = scenario_path.as_ref() {
        let raw = fs::read_to_string(path)?;
        Some(serde_json::from_str::<DebugScenario>(&raw)?)
    } else {
        None
    };

    let script_path = resolve_source_path(
        cli.script_path.as_deref(),
        scenario_path.as_deref(),
        scenario.as_ref().and_then(|s| s.script_path.as_deref()),
    )?;
    let source = fs::read_to_string(&script_path)?;
    let parsed_contract = parse_contract_ast(&source)?;
    let without_selector = cli.without_selector;

    let entrypoint_count = parsed_contract.functions.iter().filter(|func| func.entrypoint).count();
    if without_selector && entrypoint_count != 1 {
        return Err("--no-selector requires exactly one entrypoint function".into());
    }

    let scenario_active_input = scenario.as_ref().map(|s| s.active_input_index).unwrap_or(0);
    let raw_ctor_args = if !cli.raw_ctor_args.is_empty() {
        cli.raw_ctor_args.clone()
    } else if let Some(scenario) = scenario.as_ref() {
        if !scenario.constructor_args.is_empty() {
            scenario.constructor_args.clone()
        } else if let Some(per_input) = scenario.tx.inputs.get(scenario_active_input).and_then(|input| input.constructor_args.as_ref())
        {
            per_input.clone()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    let ctor_args = parse_ctor_args(&parsed_contract, &raw_ctor_args)?;

    let compile_opts = CompileOptions { record_debug_infos: true, ..Default::default() };
    let compiled = compile_contract(&source, &ctor_args, compile_opts)?;
    let debug_info = compiled.debug_info.clone();
    let mut ctor_script_cache = HashMap::<Vec<String>, Vec<u8>>::new();
    ctor_script_cache.insert(raw_ctor_args.clone(), compiled.script.clone());

    let default_name = compiled.abi.first().map(|entry| entry.name.clone()).ok_or("contract has no functions")?;
    let selected_name =
        cli.function_name.clone().or_else(|| scenario.as_ref().and_then(|s| s.function.clone())).unwrap_or(default_name);
    let entry = compiled
        .abi
        .iter()
        .find(|entry| entry.name == selected_name)
        .ok_or_else(|| format!("function '{selected_name}' not found"))?;

    let raw_args = if !cli.raw_args.is_empty() {
        cli.raw_args.clone()
    } else if let Some(scenario) = scenario.as_ref() {
        scenario.args.clone()
    } else {
        vec![]
    };
    let input_types = entry.inputs.iter().map(|input| input.type_name.clone()).collect::<Vec<_>>();
    let typed_args = parse_call_args(&input_types, &raw_args)?;

    // Always seed: even in --no-selector mode the function params must be pushed.
    let sigscript = compiled.build_sig_script(&selected_name, typed_args)?;

    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let flags = EngineFlags { covenants_enabled: true };
    if let Some(scenario) = scenario.as_ref() {
        if scenario.tx.inputs.is_empty() {
            return Err("scenario.tx.inputs must contain at least one input".into());
        }
        if scenario.active_input_index >= scenario.tx.inputs.len() {
            return Err(format!(
                "scenario.active_input_index {} out of range for {} inputs",
                scenario.active_input_index,
                scenario.tx.inputs.len()
            )
            .into());
        }

        let mut tx_inputs = Vec::with_capacity(scenario.tx.inputs.len());
        let mut utxo_specs = Vec::with_capacity(scenario.tx.inputs.len());
        for (input_idx, input) in scenario.tx.inputs.iter().enumerate() {
            let mut default_prev_txid = [0u8; 32];
            default_prev_txid.fill(input_idx as u8);
            let prev_txid = if let Some(raw_txid) = input.prev_txid.as_deref() {
                parse_txid32(raw_txid)?
            } else {
                TransactionId::from_bytes(default_prev_txid)
            };

            let input_ctor_raw = input.constructor_args.clone().unwrap_or_else(|| raw_ctor_args.clone());
            let redeem_script = if input.utxo_script_hex.is_none() {
                Some(compile_script_for_ctor_args(&source, &parsed_contract, &input_ctor_raw, &mut ctor_script_cache)?)
            } else {
                None
            };

            let signature_script = if let Some(raw_sig) = input.signature_script_hex.as_deref() {
                parse_hex_bytes(raw_sig)?
            } else if input_idx == scenario.active_input_index {
                if let Some(redeem) = redeem_script.as_ref() {
                    combine_action_and_redeem(&sigscript, redeem)?
                } else {
                    sigscript.clone()
                }
            } else if let Some(redeem) = redeem_script.as_ref() {
                sigscript_push_script(redeem)
            } else {
                vec![]
            };

            let utxo_spk = if let Some(raw_script) = input.utxo_script_hex.as_deref() {
                ScriptPublicKey::new(0, parse_hex_bytes(raw_script)?.into())
            } else {
                let redeem =
                    redeem_script.as_ref().ok_or("internal error: missing redeem script for tx input without utxo_script_hex")?;
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

        let mut tx_outputs = Vec::with_capacity(scenario.tx.outputs.len());
        for output in scenario.tx.outputs.iter() {
            let script_public_key = if let Some(raw_script) = output.script_hex.as_deref() {
                ScriptPublicKey::new(0, parse_hex_bytes(raw_script)?.into())
            } else {
                let output_ctor_raw = output.constructor_args.clone().unwrap_or_else(|| raw_ctor_args.clone());
                let output_script = compile_script_for_ctor_args(&source, &parsed_contract, &output_ctor_raw, &mut ctor_script_cache)?;
                pay_to_script_hash_script(&output_script)
            };

            let covenant = if let Some(raw) = output.covenant_id.as_deref() {
                Some(CovenantBinding {
                    authorizing_input: output.authorizing_input.unwrap_or(scenario.active_input_index as u16),
                    covenant_id: parse_hash32(raw)?,
                })
            } else {
                None
            };

            tx_outputs.push(TransactionOutput { value: output.value, script_public_key, covenant });
        }

        let tx = Transaction::new(scenario.tx.version, tx_inputs, tx_outputs, scenario.tx.lock_time, Default::default(), 0, vec![]);

        let utxos = utxo_specs
            .into_iter()
            .map(|(value, spk, covenant_id)| UtxoEntry::new(value, spk, 0, tx.is_coinbase(), covenant_id))
            .collect::<Vec<_>>();
        let populated_tx = PopulatedTransaction::new(&tx, utxos);
        let cov_ctx = CovenantsContext::from_tx(&populated_tx)?;
        let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&cov_ctx);
        let active_input = tx
            .inputs
            .get(scenario.active_input_index)
            .ok_or_else(|| format!("missing tx input at index {}", scenario.active_input_index))?;
        let active_utxo = populated_tx
            .utxo(scenario.active_input_index)
            .ok_or_else(|| format!("missing utxo entry for input {}", scenario.active_input_index))?;
        let engine =
            DebugEngine::from_transaction_input(&populated_tx, active_input, scenario.active_input_index, active_utxo, ctx, flags);
        let shadow_tx_context = ShadowTxContext {
            tx: &populated_tx,
            input: active_input,
            input_index: scenario.active_input_index,
            utxo_entry: active_utxo,
            covenants_ctx: &cov_ctx,
        };
        let mut session =
            DebugSession::full(&sigscript, &compiled.script, &source, debug_info, engine)?.with_shadow_tx_context(shadow_tx_context);

        println!("Stepping through {} bytes of script", compiled.script.len());
        session.run_to_first_executed_statement()?;
        show_source_context(&session);
        run_repl(&mut session)?;
    } else {
        let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);
        let engine = DebugEngine::new(ctx, flags);
        let mut session = DebugSession::full(&sigscript, &compiled.script, &source, debug_info, engine)?;

        println!("Stepping through {} bytes of script", compiled.script.len());
        session.run_to_first_executed_statement()?;
        show_source_context(&session);
        run_repl(&mut session)?;
    }

    Ok(())
}
