use std::collections::{HashMap, HashSet};

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{PopulatedTransaction, TransactionInput, UtxoEntry};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{DynOpcodeImplementation, EngineCtx, EngineFlags, TxScriptEngine, parse_script};
use serde::{Deserialize, Serialize};

use silverscript_lang::ast::{Expr, ExprKind};
use silverscript_lang::compiler::compile_debug_expr;
use silverscript_lang::debug_info::{
    DebugFunctionRange, DebugInfo, DebugMapping, DebugParamMapping, DebugVariableUpdate, MappingKind, SourceSpan,
};

pub use crate::presentation::{SourceContext, SourceContextLine};
use crate::presentation::{build_source_context, format_value as format_debug_value};

pub type DebugTx<'a> = PopulatedTransaction<'a>;
pub type DebugReused = SigHashReusedValuesUnsync;
pub type DebugOpcode<'a> = DynOpcodeImplementation<DebugTx<'a>, DebugReused>;
pub type DebugEngine<'a> = TxScriptEngine<'a, DebugTx<'a>, DebugReused>;

#[derive(Clone, Copy)]
pub struct ShadowTxContext<'a> {
    pub tx: &'a DebugTx<'a>,
    pub input: &'a TransactionInput,
    pub input_index: usize,
    pub utxo_entry: &'a UtxoEntry,
    pub covenants_ctx: &'a CovenantsContext,
}

#[derive(Debug, Clone)]
pub enum DebugValue {
    Int(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    String(String),
    Array(Vec<DebugValue>),
    /// Value could not be evaluated (for example unresolved identifiers or shadow VM failures).
    Unknown(std::string::String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariableOrigin {
    Local,
    Param,
    Constant,
}

impl VariableOrigin {
    pub fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Param => "arg",
            Self::Constant => "const",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Variable {
    pub name: String,
    pub type_name: String,
    pub value: DebugValue,
    pub is_constant: bool,
    pub origin: VariableOrigin,
}

#[derive(Debug, Clone)]
pub struct CallStackEntry {
    pub callee_name: String,
    pub call_site_span: Option<SourceSpan>,
    /// Sequence of the InlineCallEnter mapping (caller's context).
    pub sequence: u32,
    /// Frame ID of the InlineCallEnter mapping (caller's frame).
    pub frame_id: u32,
}

#[derive(Debug, Clone)]
pub struct FailureFrame {
    pub function_name: String,
    /// Source location: failure site for the innermost frame, call-site for callers.
    pub span: Option<SourceSpan>,
    pub variables: Vec<Variable>,
}

#[derive(Debug, Clone)]
pub struct FailureReport {
    /// Human-readable description, e.g. "require() failed".
    pub message: String,
    /// Innermost frame first.
    pub frames: Vec<FailureFrame>,
    /// Full source text for rendering context lines.
    pub source_text: String,
}

#[derive(Debug, Clone)]
pub struct SessionState {
    pub pc: usize,
    pub opcode: Option<String>,
    pub mapping: Option<DebugMapping>,
    pub stack: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackSnapshot {
    pub dstack: Vec<String>,
    pub astack: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeMeta {
    pub index: usize,
    pub byte_offset: usize,
    pub display: String,
    pub mapping: Option<DebugMapping>,
}

pub struct DebugSession<'a, 'i> {
    engine: DebugEngine<'a>,
    shadow_tx_context: Option<ShadowTxContext<'a>>,
    opcodes: Vec<Option<DebugOpcode<'a>>>,
    op_displays: Vec<String>,
    opcode_offsets: Vec<usize>,
    script_len: usize,
    pc: usize,
    debug_info: DebugInfo<'i>,
    source_mappings: Vec<DebugMapping>,
    current_step_index: Option<usize>,
    source_lines: Vec<String>,
    breakpoints: HashSet<u32>,
    // Sequence ids of steppable mappings that were already visited in this session.
    executed_sequences: HashSet<u32>,
}

struct ShadowParamValue {
    name: String,
    type_name: String,
    stack_index: i64,
    value: Vec<u8>,
}

struct VariableContext<'a> {
    function_name: &'a str,
    offset: usize,
    sequence: u32,
    frame_id: u32,
}

impl<'a, 'i> DebugSession<'a, 'i> {
    // --- Session construction + stepping ---

    /// Creates a debug session for lockscript-only execution.
    /// Use this when debugging pure contract logic without sigscript setup.
    pub fn lockscript_only(
        script: &[u8],
        source: &str,
        debug_info: Option<DebugInfo<'i>>,
        engine: DebugEngine<'a>,
    ) -> Result<Self, kaspa_txscript_errors::TxScriptError> {
        Self::from_scripts(script, source, debug_info, engine)
    }

    /// Creates a debug session simulating a full transaction spend.
    /// Executes sigscript first to seed the stack, then debugs lockscript execution.
    pub fn full(
        sigscript: &[u8],
        lockscript: &[u8],
        source: &str,
        debug_info: Option<DebugInfo<'i>>,
        mut engine: DebugEngine<'a>,
    ) -> Result<Self, kaspa_txscript_errors::TxScriptError> {
        seed_engine_with_sigscript(&mut engine, sigscript)?;
        Self::from_scripts(lockscript, source, debug_info, engine)
    }

    /// Internal constructor: parses script, prepares opcodes, extracts statement mappings.
    pub fn from_scripts(
        script: &[u8],
        source: &str,
        debug_info: Option<DebugInfo<'i>>,
        engine: DebugEngine<'a>,
    ) -> Result<Self, kaspa_txscript_errors::TxScriptError> {
        let debug_info = debug_info.unwrap_or_else(DebugInfo::empty);
        let opcodes = parse_script::<DebugTx<'a>, DebugReused>(script).collect::<Result<Vec<_>, _>>()?;
        let op_displays = opcodes.iter().map(|op| format!("{op:?}")).collect();
        let opcodes: Vec<Option<DebugOpcode<'a>>> = opcodes.into_iter().map(Some).collect();
        let source_lines: Vec<String> = source.lines().map(String::from).collect();
        let (opcode_offsets, script_len) = build_opcode_offsets(&opcodes);

        let mut source_mappings: Vec<DebugMapping> = debug_info
            .mappings
            .iter()
            .filter(|mapping| {
                matches!(
                    &mapping.kind,
                    MappingKind::Statement {}
                        | MappingKind::Virtual {}
                        | MappingKind::InlineCallEnter { .. }
                        | MappingKind::InlineCallExit { .. }
                )
            })
            .cloned()
            .collect();

        // Narrow "wrapper" Statement/Virtual mappings that span an entire inline
        // call body.  These parent mappings share bytecode_start with an
        // InlineCallEnter at the same depth and cover the whole inlined range.
        // Moving them to the exit offset avoids phantom mid-body stops and keeps
        // variable-update sequences intact.
        narrow_inline_wrapper_statements(&mut source_mappings);

        // Overlapping inline ranges can share the same bytecode offsets; keep
        // compiler emission order via sequence before comparing range width.
        source_mappings.sort_by_key(|mapping| {
            (
                mapping.bytecode_start,
                mapping.sequence,
                mapping_kind_order(&mapping.kind),
                mapping.call_depth,
                mapping.bytecode_end,
                mapping.frame_id,
            )
        });

        Ok(Self {
            engine,
            shadow_tx_context: None,
            opcodes,
            op_displays,
            opcode_offsets,
            script_len,
            pc: 0,
            debug_info,
            source_mappings,
            current_step_index: None,
            source_lines,
            breakpoints: HashSet::new(),
            executed_sequences: HashSet::new(),
        })
    }

    /// Executes a single opcode and advances the program counter.
    pub fn step_opcode(&mut self) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        if self.pc >= self.opcodes.len() {
            return Ok(None);
        }

        let opcode = self.opcodes[self.pc].take().expect("opcode already executed");
        self.engine.execute_opcode(opcode)?;
        self.pc += 1;
        self.sync_step_cursor_to_current_offset();
        Ok(Some(self.state()))
    }

    pub fn with_shadow_tx_context(mut self, shadow_tx_context: ShadowTxContext<'a>) -> Self {
        self.shadow_tx_context = Some(shadow_tx_context);
        self
    }

    /// Step into: advance to next source step regardless of call depth.
    pub fn step_into(&mut self) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        self.step_with_depth_predicate(|_, _| true)
    }

    /// Step over: advance to next source step at the same or shallower call depth.
    pub fn step_over(&mut self) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        self.step_with_depth_predicate(|candidate, current| candidate <= current)
    }

    /// Step out: advance to next source step at a shallower call depth.
    pub fn step_out(&mut self) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        self.step_with_depth_predicate(|candidate, current| candidate < current)
    }

    /// Backward-compatible statement stepping alias.
    pub fn step_statement(&mut self) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        self.step_over()
    }

    /// Shared stepping loop for `step_into`, `step_over`, and `step_out`.
    /// Picks the next steppable mapping whose call depth satisfies `predicate`,
    /// executes opcodes until that mapping becomes active, and skips candidates
    /// that are already behind the current byte offset (for example, non-taken
    /// branch mappings).
    ///
    /// `InlineCallEnter` mappings use an effective depth of `call_depth + 1`
    /// so that `step_over` (candidate <= current) skips the call boundary and
    /// `step_out` (candidate < current) does the same.  `step_into` uses an
    /// always-true predicate so the adjustment is harmless.
    fn step_with_depth_predicate(
        &mut self,
        predicate: impl Fn(u32, u32) -> bool,
    ) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        if self.source_mappings.is_empty() {
            return self.step_opcode();
        }

        let current_depth = self.current_step_mapping().map(|mapping| mapping.call_depth).unwrap_or(0);
        let mut search_from = self.current_step_index;

        loop {
            let Some(target_index) =
                self.next_steppable_mapping_index(search_from, |mapping| predicate(effective_stepping_depth(mapping), current_depth))
            else {
                return self.step_until_runtime_mapping_with_depth_predicate(|candidate| predicate(candidate, current_depth));
            };

            if self.advance_to_mapping(target_index)? {
                self.current_step_index = Some(target_index);
                self.mark_mapping_executed(target_index);
                return Ok(Some(self.state()));
            }

            search_from = Some(target_index);
        }
    }

    fn step_until_runtime_mapping_with_depth_predicate(
        &mut self,
        predicate: impl Fn(u32) -> bool,
    ) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        loop {
            if self.step_opcode()?.is_none() {
                return Ok(None);
            }

            if !self.engine.is_executing() {
                continue;
            }

            let offset = self.current_byte_offset();
            let Some(index) = self.steppable_mapping_index_for_offset(offset) else {
                continue;
            };

            if self.current_step_index == Some(index) {
                continue;
            }

            let Some(mapping) = self.source_mappings.get(index) else {
                continue;
            };

            if !predicate(effective_stepping_depth(mapping)) {
                continue;
            }

            self.current_step_index = Some(index);
            self.mark_mapping_executed(index);
            return Ok(Some(self.state()));
        }
    }

    fn advance_to_mapping(&mut self, target_index: usize) -> Result<bool, kaspa_txscript_errors::TxScriptError> {
        let Some(target) = self.source_mappings.get(target_index).cloned() else {
            return Ok(false);
        };
        loop {
            let offset = self.current_byte_offset();

            if offset > target.bytecode_start {
                return Ok(false);
            }

            if mapping_matches_offset(&target, offset) && self.engine.is_executing() {
                return Ok(true);
            }

            if self.step_opcode()?.is_none() {
                return Ok(false);
            }
        }
    }

    /// Advances execution to the first user statement, skipping dispatcher/synthetic bytecode.
    /// Call this after session creation to skip over contract setup code.
    /// Skips opcodes until the first source-mapped statement is encountered.
    pub fn run_to_first_executed_statement(&mut self) -> Result<(), kaspa_txscript_errors::TxScriptError> {
        if self.source_mappings.is_empty() {
            return Ok(());
        }
        loop {
            if self.pc >= self.opcodes.len() {
                return Ok(());
            }
            let offset = self.current_byte_offset();
            if self.engine.is_executing() {
                if let Some(index) = self.steppable_mapping_index_for_offset(offset) {
                    self.current_step_index = Some(index);
                    self.mark_mapping_executed(index);
                    return Ok(());
                }
            }
            if self.step_opcode()?.is_none() {
                return Ok(());
            }
        }
    }

    /// Continues execution until a breakpoint is hit or script completes.
    pub fn continue_to_breakpoint(&mut self) -> Result<Option<SessionState>, kaspa_txscript_errors::TxScriptError> {
        if self.breakpoints.is_empty() {
            while self.step_opcode()?.is_some() {}
            return Ok(None);
        }
        loop {
            if self.step_into()?.is_none() {
                return Ok(None);
            }
            if let Some(mapping) = self.current_step_mapping() {
                // Ignore synthetic zero-width parent wrappers emitted at inline
                // call exits; otherwise call-site breakpoints can re-trigger
                // after returning from the inlined callee.
                if is_inline_exit_wrapper_marker(mapping, &self.source_mappings) {
                    continue;
                }
                if self.mapping_hits_breakpoint(mapping) {
                    return Ok(Some(self.state()));
                }
            }
        }
    }

    /// Returns the current execution state snapshot.
    pub fn state(&self) -> SessionState {
        let executed = self.pc.saturating_sub(1);
        let opcode = self.op_displays.get(executed).cloned();
        SessionState { pc: self.pc, opcode, mapping: self.current_location(), stack: self.stack() }
    }

    /// Returns true if the script engine is still running.
    pub fn is_executing(&self) -> bool {
        self.engine.is_executing()
    }

    /// Returns the current data and alt stack contents.
    pub fn stacks_snapshot(&self) -> StackSnapshot {
        let stacks = self.engine.stacks();
        StackSnapshot {
            dstack: stacks.dstack.iter().map(|item| encode_hex(item)).collect(),
            astack: stacks.astack.iter().map(|item| encode_hex(item)).collect(),
        }
    }

    /// Returns metadata for all opcodes (executed/pending status, byte offset).
    pub fn opcode_metas(&self) -> Vec<OpcodeMeta> {
        (0..self.op_displays.len())
            .map(|index| {
                let byte_offset = self.opcode_offsets.get(index).copied().unwrap_or(self.script_len);
                OpcodeMeta {
                    index,
                    byte_offset,
                    display: self.op_displays.get(index).cloned().unwrap_or_default(),
                    mapping: self.mapping_for_offset(byte_offset).cloned(),
                }
            })
            .collect()
    }

    /// Returns the total number of opcodes in the script.
    pub fn opcode_count(&self) -> usize {
        self.op_displays.len()
    }

    pub fn debug_info(&self) -> &DebugInfo<'i> {
        &self.debug_info
    }

    // --- Mapping + source context ---

    /// Returns source lines around the current statement (radius = 6 lines).
    /// Active line is marked via `is_active` field. Returns None if no source mapping exists.
    /// Returns surrounding source lines with the current line highlighted.
    pub fn source_context(&self) -> Option<SourceContext> {
        let span = self.current_span()?;
        Some(build_source_context(&self.source_lines, span, 6))
    }

    /// Adds a breakpoint at the given line number. Returns true if added.
    pub fn add_breakpoint(&mut self, line: u32) -> bool {
        self.add_breakpoint_resolved(line).is_some()
    }

    pub fn add_breakpoint_resolved(&mut self, line: u32) -> Option<u32> {
        let resolved = self.resolve_breakpoint_line(line)?;
        self.breakpoints.insert(resolved);
        Some(resolved)
    }

    pub fn resolve_breakpoint_line(&self, requested_line: u32) -> Option<u32> {
        let mut containing_start: Option<u32> = None;
        let mut next_after: Option<u32> = None;

        for mapping in self.source_mappings.iter().filter(|mapping| self.is_steppable_mapping(mapping)) {
            let Some(span) = mapping.span else {
                continue;
            };

            if span.line == requested_line {
                return Some(span.line);
            }

            if requested_line >= span.line && requested_line <= span.end_line {
                containing_start = match containing_start {
                    Some(current) if current >= span.line => Some(current),
                    _ => Some(span.line),
                };
            }

            if span.line >= requested_line {
                next_after = match next_after {
                    Some(current) if current <= span.line => Some(current),
                    _ => Some(span.line),
                };
            }
        }

        containing_start.or(next_after)
    }

    /// Returns all currently set breakpoint line numbers.
    pub fn breakpoints(&self) -> Vec<u32> {
        let mut lines = self.breakpoints.iter().copied().collect::<Vec<_>>();
        lines.sort_unstable();
        lines
    }

    /// Removes the breakpoint at the given line number.
    pub fn clear_breakpoint(&mut self, line: u32) {
        self.breakpoints.remove(&line);
    }

    // --- Variable inspection ---

    /// Returns all variables in scope at current execution point.
    /// Includes params, local variables (up to current offset), and constructor constants.
    /// Values are computed via shadow VM evaluation.
    pub fn list_variables(&self) -> Result<Vec<Variable>, String> {
        let (sequence, frame_id) = self.current_step_sequence_and_frame();
        self.collect_variables(sequence, frame_id)
    }

    pub fn list_variables_at_sequence(&self, sequence: u32, frame_id: u32) -> Result<Vec<Variable>, String> {
        self.collect_variables(sequence, frame_id)
    }

    fn collect_variables(&self, sequence: u32, frame_id: u32) -> Result<Vec<Variable>, String> {
        let context = self.current_variable_context(sequence, frame_id)?;
        let mut variables = self.collect_variables_map(&context)?.into_values().collect::<Vec<_>>();
        variables.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(variables)
    }

    /// Returns a specific variable by name, or error if not in scope.
    pub fn variable_by_name(&self, name: &str) -> Result<Variable, String> {
        let (sequence, frame_id) = self.current_step_sequence_and_frame();
        let context = self.current_variable_context(sequence, frame_id)?;
        let variables = self.collect_variables_map(&context)?;
        variables.get(name).cloned().ok_or_else(|| format!("unknown variable '{name}'"))
    }

    // --- DebugValue formatting ---
    /// Formats a debug value for display based on its type.
    pub fn format_value(&self, type_name: &str, value: &DebugValue) -> String {
        format_debug_value(type_name, value)
    }

    /// Returns the debug mapping for the current bytecode position.
    pub fn current_location(&self) -> Option<DebugMapping> {
        self.current_step_mapping().cloned().or_else(|| self.mapping_for_offset(self.current_byte_offset()).cloned())
    }

    /// Returns the current bytecode offset in the script.
    pub fn current_byte_offset(&self) -> usize {
        self.opcode_offsets.get(self.pc).copied().unwrap_or(self.script_len)
    }

    /// Returns the source span (line/col range) at the current position.
    pub fn current_span(&self) -> Option<SourceSpan> {
        self.current_location().and_then(|mapping| mapping.span)
    }

    pub fn call_stack(&self) -> Vec<String> {
        self.call_stack_with_spans().into_iter().map(|entry| entry.callee_name).collect()
    }

    /// Returns the call stack with per-frame call-site spans and mapping metadata.
    /// Each entry is `(callee_name, call_site_span, sequence, frame_id)` where
    /// `sequence`/`frame_id` belong to the `InlineCallEnter` mapping (the caller's frame).
    pub fn call_stack_with_spans(&self) -> Vec<CallStackEntry> {
        let mut stack: Vec<CallStackEntry> = Vec::new();
        let Some(current) = self.current_step_index else {
            return stack;
        };
        for mapping in self.source_mappings.iter().take(current + 1) {
            match &mapping.kind {
                MappingKind::InlineCallEnter { callee } => stack.push(CallStackEntry {
                    callee_name: callee.clone(),
                    call_site_span: mapping.span,
                    sequence: mapping.sequence,
                    frame_id: mapping.frame_id,
                }),
                MappingKind::InlineCallExit { .. } => {
                    stack.pop();
                }
                _ => {}
            }
        }
        stack
    }

    /// Builds a structured failure report from the given script error.
    /// Captures the failure site, call stack, and per-frame variable values.
    pub fn build_failure_report(&self, error: &kaspa_txscript_errors::TxScriptError) -> FailureReport {
        // When execute_opcode fails, pc still points at the failing opcode.
        // Use the raw bytecode offset to resolve the actual failure mapping
        // (e.g. the require() line inside a callee), rather than the stepper
        // cursor which may point at the call site.
        let failure_offset = self.current_byte_offset();
        let failure_mapping = self.mapping_for_offset(failure_offset);
        let failure_span = failure_mapping.and_then(|m| m.span).or_else(|| self.current_span());

        let call_stack = self.call_stack_with_spans();

        // --- Innermost frame: the function where the failure actually occurred ---
        let innermost_function = if let Some(last_callee) = call_stack.last() {
            last_callee.callee_name.clone()
        } else {
            self.current_function_name().unwrap_or("<entry>").to_string()
        };

        // Variables for the innermost (callee) frame: use the failure mapping's
        // sequence/frame_id so we resolve *callee* locals, not the caller's.
        let innermost_vars = if let Some(fm) = failure_mapping {
            self.list_variables_at_sequence(fm.sequence, fm.frame_id).unwrap_or_default()
        } else {
            self.list_variables().unwrap_or_default()
        };
        // Filter out constants — they're contract-scoped and just add noise.
        let innermost_vars: Vec<Variable> = innermost_vars.into_iter().filter(|v| !v.is_constant).collect();

        let mut frames = vec![FailureFrame { function_name: innermost_function, span: failure_span, variables: innermost_vars }];

        // --- Caller frames: build from the call stack ---
        // call_stack is ordered outermost-first → innermost-last.
        // We walk from the innermost caller to the outermost, each entry's
        // sequence/frame_id identifies the *caller's* frame context.
        let entry_name = self.current_function_name().unwrap_or("<entry>").to_string();
        for idx in (0..call_stack.len()).rev() {
            let entry = &call_stack[idx];
            let caller_vars = self
                .list_variables_at_sequence(entry.sequence, entry.frame_id)
                .unwrap_or_default()
                .into_iter()
                .filter(|v| !v.is_constant)
                .collect();
            // The caller is the entrypoint for the outermost call,
            // or the callee name from the previous (outer) entry.
            let caller_name = if idx == 0 { entry_name.clone() } else { call_stack[idx - 1].callee_name.clone() };
            frames.push(FailureFrame { function_name: caller_name, span: entry.call_site_span, variables: caller_vars });
        }

        let message = format!("{error}");
        FailureReport { message, frames, source_text: self.source_lines.join("\n") }
    }

    /// Returns the name of the function currently being executed.
    pub fn current_function_name(&self) -> Option<&str> {
        self.current_function_range().map(|range| range.name.as_str())
    }

    fn current_function_range(&self) -> Option<&DebugFunctionRange> {
        self.function_range_for_offset(self.current_byte_offset())
    }

    fn function_range_for_offset(&self, offset: usize) -> Option<&DebugFunctionRange> {
        self.debug_info.functions.iter().find(|function| offset >= function.bytecode_start && offset < function.bytecode_end)
    }

    fn mapping_for_sequence_and_frame(&self, sequence: u32, frame_id: u32) -> Option<&DebugMapping> {
        self.source_mappings
            .iter()
            .find(|mapping| mapping.sequence == sequence && mapping.frame_id == frame_id)
            .or_else(|| self.debug_info.mappings.iter().find(|mapping| mapping.sequence == sequence && mapping.frame_id == frame_id))
    }

    fn current_variable_updates(
        &self,
        function_name: &str,
        offset: usize,
        sequence: u32,
        frame_id: u32,
    ) -> HashMap<String, &DebugVariableUpdate<'i>> {
        let mut latest: HashMap<String, &DebugVariableUpdate<'i>> = HashMap::new();
        for update in self
            .debug_info
            .variable_updates
            .iter()
            .filter(|update| self.update_is_visible(update, function_name, offset, sequence, frame_id))
        {
            match latest.get(&update.name) {
                Some(existing) if existing.sequence > update.sequence => {}
                _ => {
                    latest.insert(update.name.clone(), update);
                }
            }
        }
        latest
    }

    fn current_variable_context(&self, sequence: u32, frame_id: u32) -> Result<VariableContext<'_>, String> {
        let (current_sequence, current_frame_id) = self.current_step_sequence_and_frame();
        if sequence == current_sequence && frame_id == current_frame_id {
            let function_name = self.current_function_name().ok_or_else(|| "No function context available".to_string())?;
            return Ok(VariableContext { function_name, offset: self.current_byte_offset(), sequence, frame_id });
        }

        if let Some(mapping) = self.mapping_for_sequence_and_frame(sequence, frame_id) {
            let offset = mapping.bytecode_start;
            let function_name = self
                .function_range_for_offset(offset)
                .map(|range| range.name.as_str())
                .or_else(|| self.current_function_name())
                .ok_or_else(|| "No function context available".to_string())?;
            return Ok(VariableContext { function_name, offset, sequence, frame_id });
        }

        let function_name = self.current_function_name().ok_or_else(|| "No function context available".to_string())?;
        Ok(VariableContext { function_name, offset: self.current_byte_offset(), sequence, frame_id })
    }

    fn collect_variables_map(&self, context: &VariableContext<'_>) -> Result<HashMap<String, Variable>, String> {
        let mut variables: HashMap<String, Variable> = HashMap::new();
        let var_updates = self.current_variable_updates(context.function_name, context.offset, context.sequence, context.frame_id);

        for (name, update) in &var_updates {
            let value = self.evaluate_update_with_shadow_vm(context.function_name, update).unwrap_or_else(DebugValue::Unknown);
            variables.insert(
                name.clone(),
                Variable {
                    name: name.clone(),
                    type_name: update.type_name.clone(),
                    value,
                    is_constant: false,
                    origin: VariableOrigin::Local,
                },
            );
        }

        for param in self.debug_info.params.iter().filter(|param| param.function == context.function_name) {
            if variables.contains_key(&param.name) {
                continue;
            }
            let value = self.read_param_value(param)?;
            variables.insert(
                param.name.clone(),
                Variable {
                    name: param.name.clone(),
                    type_name: param.type_name.clone(),
                    value,
                    is_constant: false,
                    origin: VariableOrigin::Param,
                },
            );
        }

        // Contract constants are contract-scoped, not frame-scoped, so they
        // remain visible while stepping through inline callee frames.
        for constant in &self.debug_info.constants {
            if variables.contains_key(&constant.name) {
                continue;
            }
            variables.insert(
                constant.name.clone(),
                Variable {
                    name: constant.name.clone(),
                    type_name: constant.type_name.clone(),
                    value: self.evaluate_constant(&constant.value),
                    is_constant: true,
                    origin: VariableOrigin::Constant,
                },
            );
        }

        Ok(variables)
    }

    fn update_is_visible(
        &self,
        update: &DebugVariableUpdate<'i>,
        function_name: &str,
        offset: usize,
        sequence: u32,
        frame_id: u32,
    ) -> bool {
        if update.function != function_name {
            return false;
        }
        // Stay in the active inline frame and only consider updates from
        // steps already executed in this session.
        update.frame_id == frame_id
            && self.executed_sequences.contains(&update.sequence)
            && update.sequence < sequence
            && update.bytecode_offset <= offset
    }

    /// Returns the most specific mapping for `offset`.
    /// Multiple mappings may overlap; choosing the narrowest bytecode span makes
    /// location lookups prefer inner statement/inline ranges over broader ranges.
    fn mapping_for_offset(&self, offset: usize) -> Option<&DebugMapping> {
        let mut best: Option<&DebugMapping> = None;
        let mut best_len = usize::MAX;
        for mapping in &self.debug_info.mappings {
            if mapping_matches_offset(mapping, offset) {
                let len = mapping.bytecode_end.saturating_sub(mapping.bytecode_start);
                if len < best_len {
                    best = Some(mapping);
                    best_len = len;
                }
            }
        }
        best
    }

    fn current_step_mapping(&self) -> Option<&DebugMapping> {
        self.current_step_index.and_then(|index| self.source_mappings.get(index))
    }

    fn current_step_sequence_and_frame(&self) -> (u32, u32) {
        // Sequence/frame identify the statement context used for variable filtering.
        self.current_step_mapping().map(|mapping| (mapping.sequence, mapping.frame_id)).unwrap_or((0, 0))
    }

    fn mark_mapping_executed(&mut self, mapping_index: usize) {
        if let Some(mapping) = self.source_mappings.get(mapping_index) {
            self.executed_sequences.insert(mapping.sequence);
        }
    }

    fn sync_step_cursor_to_current_offset(&mut self) {
        let offset = self.current_byte_offset();
        if let Some(index) = self.steppable_mapping_index_for_offset(offset) {
            if self.current_step_index.is_some_and(|current| index < current) {
                // In sequence mode multiple steps may map to the same byte offset.
                // Keep cursor monotonic and avoid snapping backward to an earlier
                // mapping for that offset.
                return;
            }
            // `si` executes raw opcodes; keep statement cursor in sync so later
            // source-level steps (`next`/`step`/`finish`) start from the real
            // current mapping instead of an old one.
            self.current_step_index = Some(index);
            self.mark_mapping_executed(index);
        }
    }

    fn is_steppable_mapping(&self, mapping: &DebugMapping) -> bool {
        // InlineCallEnter is steppable so `step_into` can land on a call
        // boundary and build call-stack transitions. InlineCallExit is not
        // steppable to avoid synthetic extra stops while unwinding.
        matches!(&mapping.kind, MappingKind::Statement {} | MappingKind::Virtual {} | MappingKind::InlineCallEnter { .. })
    }

    fn steppable_mapping_index_for_offset(&self, offset: usize) -> Option<usize> {
        self.source_mappings
            .iter()
            .enumerate()
            .find(|(_, mapping)| self.is_steppable_mapping(mapping) && mapping_matches_offset(mapping, offset))
            .map(|(index, _)| index)
    }

    fn next_steppable_mapping_index(&self, from: Option<usize>, predicate: impl Fn(&DebugMapping) -> bool) -> Option<usize> {
        let start = from.map(|index| index.saturating_add(1)).unwrap_or(0);
        for index in start..self.source_mappings.len() {
            let mapping = self.source_mappings.get(index)?;
            if !self.is_steppable_mapping(mapping) {
                continue;
            }
            if predicate(mapping) {
                return Some(index);
            }
        }
        None
    }

    fn mapping_hits_breakpoint(&self, mapping: &DebugMapping) -> bool {
        mapping.span.map(|span| self.breakpoints.contains(&span.line)).unwrap_or(false)
    }

    /// Returns the current main stack as hex-encoded strings.
    pub fn stack(&self) -> Vec<String> {
        let stacks = self.engine.stacks();
        stacks.dstack.iter().map(|item| encode_hex(item)).collect()
    }

    fn evaluate_update_with_shadow_vm(&self, function_name: &str, update: &DebugVariableUpdate<'i>) -> Result<DebugValue, String> {
        self.evaluate_expr_with_shadow_vm(function_name, &update.type_name, &update.expr)
    }

    /// Evaluates an expression using shadow VM execution.
    ///
    /// Strategy: compile the pre-resolved expression to bytecode, build a mini-script
    /// that pushes current param values then executes the bytecode, run on fresh VM,
    /// read result from top of stack. This guarantees debugger sees same semantics as
    /// real execution without duplicating evaluation logic.
    fn evaluate_expr_with_shadow_vm(&self, function_name: &str, type_name: &str, expr: &Expr<'i>) -> Result<DebugValue, String> {
        let params = self.shadow_param_values(function_name)?;
        let mut param_indexes = HashMap::new();
        let mut param_types = HashMap::new();
        for param in &params {
            param_indexes.insert(param.name.clone(), param.stack_index);
            param_types.insert(param.name.clone(), param.type_name.clone());
        }
        let bytecode = compile_debug_expr(expr, &param_indexes, &param_types)
            .map_err(|err| format!("failed to compile debug expression: {err}"))?;
        let script = self.build_shadow_script(&params, &bytecode)?;
        let bytes = self.execute_shadow_script(&script)?;
        decode_value_by_type(type_name, bytes)
    }

    fn shadow_param_values(&self, function_name: &str) -> Result<Vec<ShadowParamValue>, String> {
        let mut params = Vec::new();
        for param in self.debug_info.params.iter().filter(|param| param.function == function_name) {
            params.push(ShadowParamValue {
                name: param.name.clone(),
                type_name: param.type_name.clone(),
                stack_index: param.stack_index,
                value: self.read_stack_at_index(param.stack_index)?,
            });
        }
        // Push higher stack indexes first so index 0 remains the top parameter.
        params.sort_by(|left, right| right.stack_index.cmp(&left.stack_index));
        Ok(params)
    }

    fn build_shadow_script(&self, params: &[ShadowParamValue], expr_bytecode: &[u8]) -> Result<Vec<u8>, String> {
        let mut builder = ScriptBuilder::new();
        for param in params {
            builder.add_data(&param.value).map_err(|err| err.to_string())?;
        }
        builder.add_ops(expr_bytecode).map_err(|err| err.to_string())?;
        Ok(builder.drain())
    }

    fn execute_shadow_script(&self, script: &[u8]) -> Result<Vec<u8>, String> {
        let sig_cache = Cache::new(0);
        let reused_values = SigHashReusedValuesUnsync::new();
        let mut engine: DebugEngine<'_> = if let Some(shadow) = self.shadow_tx_context {
            let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(shadow.covenants_ctx);
            TxScriptEngine::from_transaction_input(
                shadow.tx,
                shadow.input,
                shadow.input_index,
                shadow.utxo_entry,
                ctx,
                EngineFlags { covenants_enabled: true },
            )
        } else {
            TxScriptEngine::new(EngineCtx::new(&sig_cache).with_reused(&reused_values), EngineFlags { covenants_enabled: true })
        };
        for opcode in parse_script::<DebugTx<'_>, DebugReused>(script) {
            let opcode = opcode.map_err(|err| format!("failed to parse shadow script: {err}"))?;
            engine.execute_opcode(opcode).map_err(|err| format!("failed to execute shadow script: {err}"))?;
        }
        engine.stacks().dstack.last().cloned().ok_or_else(|| "shadow VM produced an empty stack".to_string())
    }

    fn read_param_value(&self, param: &DebugParamMapping) -> Result<DebugValue, String> {
        let bytes = self.read_stack_at_index(param.stack_index)?;
        decode_value_by_type(&param.type_name, bytes)
    }

    fn evaluate_constant(&self, expr: &Expr<'i>) -> DebugValue {
        match &expr.kind {
            ExprKind::Int(v) => DebugValue::Int(*v),
            ExprKind::Bool(v) => DebugValue::Bool(*v),
            ExprKind::Byte(v) => DebugValue::Bytes(vec![*v]),
            ExprKind::String(v) => DebugValue::String(v.clone()),
            _ => DebugValue::Unknown("complex expression".to_string()),
        }
    }

    fn read_stack_at_index(&self, index: i64) -> Result<Vec<u8>, String> {
        if index < 0 {
            return Err("negative stack index".to_string());
        }
        let stacks = self.engine.stacks();
        let stack = stacks.dstack;
        let idx = index as usize;
        if idx >= stack.len() {
            return Err("stack index out of range".to_string());
        }
        let stack_index = stack.len() - 1 - idx;
        Ok(stack.get(stack_index).cloned().unwrap_or_default())
    }
}

/// Decodes raw bytes into a typed debug value based on the type name.
fn decode_value_by_type(type_name: &str, bytes: Vec<u8>) -> Result<DebugValue, String> {
    match type_name {
        "int" => Ok(DebugValue::Int(decode_i64(&bytes)?)),
        "bool" => Ok(DebugValue::Bool(decode_i64(&bytes)? != 0)),
        "string" => match String::from_utf8(bytes.clone()) {
            Ok(value) => Ok(DebugValue::String(value)),
            Err(_) => Ok(DebugValue::Bytes(bytes)),
        },
        _ => Ok(DebugValue::Bytes(bytes)),
    }
}

/// Decodes a txscript script number (little-endian sign-magnitude, max 8 bytes).
/// Mirrors txscript's internal numeric decode logic; kept local because txscript
/// exposes this helper only as crate-private internals today.
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

/// Executes sigscript to seed the stack before debugging lockscript.
fn seed_engine_with_sigscript(engine: &mut DebugEngine<'_>, sigscript: &[u8]) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    for opcode in parse_script::<DebugTx<'_>, DebugReused>(sigscript) {
        engine.execute_opcode(opcode?)?;
    }
    Ok(())
}

fn build_opcode_offsets(opcodes: &[Option<DebugOpcode<'_>>]) -> (Vec<usize>, usize) {
    let mut offsets = Vec::with_capacity(opcodes.len() + 1);
    let mut offset = 0usize;
    for opcode in opcodes {
        offsets.push(offset);
        if let Some(op) = opcode {
            offset = offset.saturating_add(op.serialize().len());
        }
    }
    (offsets, offset)
}

fn mapping_kind_order(kind: &MappingKind) -> u8 {
    match kind {
        MappingKind::InlineCallEnter { .. } => 0,
        MappingKind::Virtual {} => 1,
        MappingKind::Statement {} => 2,
        MappingKind::InlineCallExit { .. } => 3,
        MappingKind::Synthetic { .. } => 4,
    }
}

fn mapping_matches_offset(mapping: &DebugMapping, offset: usize) -> bool {
    if mapping.bytecode_start == mapping.bytecode_end {
        offset == mapping.bytecode_start
    } else {
        offset >= mapping.bytecode_start && offset < mapping.bytecode_end
    }
}

/// Returns the effective call depth used for stepping predicates.
///
/// `InlineCallEnter` sits at the *caller's* depth but semantically transitions
/// into a deeper frame.  Treating it as `depth + 1` allows `step_over`
/// (`candidate <= current`) and `step_out` (`candidate < current`) to skip
/// past the call boundary and the entire inlined body in one go.
fn effective_stepping_depth(mapping: &DebugMapping) -> u32 {
    if matches!(&mapping.kind, MappingKind::InlineCallEnter { .. }) {
        mapping.call_depth.saturating_add(1)
    } else {
        mapping.call_depth
    }
}

/// Narrows "wrapper" Statement/Virtual mappings that span an entire inline call
/// body so they become zero-width markers at the call-exit offset.
///
/// A wrapper mapping is a Statement/Virtual at depth D whose `bytecode_start`
/// matches an `InlineCallEnter` at the same depth, and whose `bytecode_end` is
/// at or past the matching `InlineCallExit`.  Moving it to `(exit, exit)` means
/// it sorts after all callee-body events and only matches when the PC has
/// actually advanced past the inlined code.
fn narrow_inline_wrapper_statements(mappings: &mut [DebugMapping]) {
    // Build map: (bytecode_start, call_depth) of each InlineCallEnter →
    // bytecode_start of the closest matching InlineCallExit at the same depth.
    let enter_offsets: Vec<(usize, u32)> = mappings
        .iter()
        .filter(|m| matches!(&m.kind, MappingKind::InlineCallEnter { .. }))
        .map(|m| (m.bytecode_start, m.call_depth))
        .collect();

    let exit_by_enter: HashMap<(usize, u32), usize> = enter_offsets
        .iter()
        .filter_map(|&(start, depth)| {
            mappings
                .iter()
                .filter(|m| matches!(&m.kind, MappingKind::InlineCallExit { .. }))
                .filter(|m| m.call_depth == depth && m.bytecode_start > start)
                .min_by_key(|m| m.bytecode_start)
                .map(|m| ((start, depth), m.bytecode_start))
        })
        .collect();

    for mapping in mappings.iter_mut() {
        if !matches!(&mapping.kind, MappingKind::Statement {} | MappingKind::Virtual {}) {
            continue;
        }
        if let Some(&exit_offset) = exit_by_enter.get(&(mapping.bytecode_start, mapping.call_depth)) {
            // Only narrow if this mapping actually wraps the inline body (wider
            // than the enter marker and reaching at least the exit offset).
            if mapping.bytecode_end > mapping.bytecode_start && mapping.bytecode_end >= exit_offset {
                mapping.bytecode_start = exit_offset;
                mapping.bytecode_end = exit_offset;
            }
        }
    }
}

/// Returns true when `mapping` is the zero-width parent wrapper marker that
/// sits at an inline-call exit offset after narrowing.
fn is_inline_exit_wrapper_marker(mapping: &DebugMapping, mappings: &[DebugMapping]) -> bool {
    if !matches!(&mapping.kind, MappingKind::Statement {} | MappingKind::Virtual {}) {
        return false;
    }
    if mapping.bytecode_start != mapping.bytecode_end {
        return false;
    }
    mappings.iter().any(|candidate| {
        matches!(&candidate.kind, MappingKind::InlineCallExit { .. })
            && candidate.call_depth == mapping.call_depth
            && candidate.bytecode_start == mapping.bytecode_start
            && candidate.bytecode_end == mapping.bytecode_end
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = vec![0u8; bytes.len() * 2];
    if faster_hex::hex_encode(bytes, &mut out).is_err() {
        return String::new();
    }
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    use silverscript_lang::ast::{BinaryOp, Expr, ExprKind};
    use silverscript_lang::debug_info::{
        DebugConstantMapping, DebugFunctionRange, DebugInfo, DebugMapping, DebugParamMapping, DebugVariableUpdate, MappingKind,
        SourceSpan,
    };
    use silverscript_lang::span;

    fn make_session(
        params: Vec<DebugParamMapping>,
        updates: Vec<DebugVariableUpdate<'static>>,
        sigscript: &[u8],
    ) -> Result<DebugSession<'static, 'static>, kaspa_txscript_errors::TxScriptError> {
        let sig_cache = Box::leak(Box::new(Cache::new(10_000)));
        let reused_values: &'static SigHashReusedValuesUnsync = Box::leak(Box::new(SigHashReusedValuesUnsync::new()));
        let engine: DebugEngine<'static> =
            TxScriptEngine::new(EngineCtx::new(sig_cache).with_reused(reused_values), EngineFlags { covenants_enabled: true });
        let debug_info = DebugInfo {
            source: String::new(),
            mappings: vec![],
            variable_updates: updates,
            params,
            functions: vec![DebugFunctionRange { name: "f".to_string(), bytecode_start: 0, bytecode_end: 1 }],
            constants: vec![DebugConstantMapping { name: "K".to_string(), type_name: "int".to_string(), value: Expr::int(7) }],
        };
        DebugSession::full(sigscript, &[], "", Some(debug_info), engine)
    }

    #[test]
    fn decode_i64_handles_basic_values() {
        assert_eq!(decode_i64(&[]).unwrap(), 0);
        assert_eq!(decode_i64(&[1]).unwrap(), 1);
        assert_eq!(decode_i64(&[0x81]).unwrap(), -1);
        assert_eq!(decode_i64(&[0, 0x80]).unwrap(), 0);
    }

    #[test]
    fn shadow_vm_evaluates_param_expression() {
        let mut sig_builder = ScriptBuilder::new();
        sig_builder.add_i64(3).unwrap();
        sig_builder.add_i64(9).unwrap();
        let sigscript = sig_builder.drain();

        let session = make_session(
            vec![
                DebugParamMapping { name: "a".to_string(), type_name: "int".to_string(), stack_index: 1, function: "f".to_string() },
                DebugParamMapping { name: "b".to_string(), type_name: "int".to_string(), stack_index: 0, function: "f".to_string() },
            ],
            vec![],
            &sigscript,
        )
        .unwrap();

        let value = session
            .evaluate_expr_with_shadow_vm(
                "f",
                "int",
                &Expr::new(
                    ExprKind::Binary {
                        op: BinaryOp::Add,
                        left: Box::new(Expr::identifier("a")),
                        right: Box::new(Expr::identifier("b")),
                    },
                    span::Span::default(),
                ),
            )
            .unwrap();
        assert!(matches!(value, DebugValue::Int(12)));
    }

    #[test]
    fn list_variables_returns_unknown_for_uncompilable_expr() {
        let mut sig_builder = ScriptBuilder::new();
        sig_builder.add_i64(5).unwrap();
        let sigscript = sig_builder.drain();

        let mut session = make_session(
            vec![DebugParamMapping { name: "a".to_string(), type_name: "int".to_string(), stack_index: 0, function: "f".to_string() }],
            vec![DebugVariableUpdate {
                name: "x".to_string(),
                type_name: "int".to_string(),
                expr: Expr::identifier("missing"),
                bytecode_offset: 0,
                span: None,
                function: "f".to_string(),
                sequence: 0,
                frame_id: 0,
            }],
            &sigscript,
        )
        .unwrap();

        session.executed_sequences.insert(0);
        // In sequence-only mode, query visibility at an explicit sequence that
        // is after the update's sequence.
        let vars = session.list_variables_at_sequence(1, 0).unwrap();
        let x = vars.into_iter().find(|var| var.name == "x").expect("x variable");
        assert!(matches!(x.value, DebugValue::Unknown(_)));
    }

    #[test]
    fn step_into_falls_back_to_runtime_mapping_when_no_forward_index_exists() {
        let sig_cache = Box::leak(Box::new(Cache::new(10_000)));
        let reused_values: &'static SigHashReusedValuesUnsync = Box::leak(Box::new(SigHashReusedValuesUnsync::new()));
        let engine: DebugEngine<'static> =
            TxScriptEngine::new(EngineCtx::new(sig_cache).with_reused(reused_values), EngineFlags { covenants_enabled: true });

        // Script with two opcodes so stepping reaches byte offset 1.
        let script = vec![0x51, 0x51];
        let debug_info = DebugInfo {
            source: String::new(),
            mappings: vec![
                DebugMapping {
                    bytecode_start: 1,
                    bytecode_end: 2,
                    span: Some(SourceSpan { line: 10, col: 1, end_line: 10, end_col: 5 }),
                    kind: MappingKind::Statement {},
                    sequence: 1,
                    frame_id: 0,
                    call_depth: 0,
                },
                DebugMapping {
                    bytecode_start: 1,
                    bytecode_end: 2,
                    span: Some(SourceSpan { line: 11, col: 1, end_line: 11, end_col: 5 }),
                    kind: MappingKind::Statement {},
                    sequence: 2,
                    frame_id: 0,
                    call_depth: 0,
                },
            ],
            variable_updates: vec![],
            params: vec![],
            functions: vec![DebugFunctionRange { name: "f".to_string(), bytecode_start: 0, bytecode_end: 2 }],
            constants: vec![],
        };

        let mut session = DebugSession::lockscript_only(&script, "", Some(debug_info), engine).expect("session");

        // Simulate cursor being on the later mapping index with no forward candidates.
        session.current_step_index = Some(1);

        let state = session.step_into().expect("step_into should succeed");
        assert!(state.is_some(), "fallback stepping should stop at a runtime mapping");
        let span = session.current_span().expect("span after fallback step");
        assert_eq!(span.line, 10);
    }
}
