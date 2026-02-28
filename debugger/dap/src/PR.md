
## PR: DAP Debug Adapter + Sidecar Test System + CodeLens + VS Code Testing API

### Summary

This PR adds a full **Debug Adapter Protocol (DAP)** implementation for SilverScript, a **sidecar test file** system (`*.test.json`), **CodeLens** inline actions, and **VS Code native Testing API** integration — enabling one-click Run/Debug/Test directly from contract source code. It also includes a **boundary test generator** that auto-creates test cases from function signatures.

**27 files changed, +3798 / -148 lines**

---

### What's New

| Feature | Description |
|---------|-------------|
| **DAP Adapter** | Full DAP protocol implementation in Rust — launch, breakpoints, step (next/in/out), continue, variables, scopes, stack traces |
| **Sidecar Tests** | `*.test.json` files alongside `*.sil` contracts define named test cases with args, expectations, and optional tx context |
| **Transaction Context** | Tests can specify full transaction inputs/outputs/covenants — the adapter builds a real `PopulatedTransaction` for debugging |
| **CodeLens** | `▶ Run | 🐛 Debug | ✚ Test | 🧪 N tests` above every `entrypoint function` |
| **Testing API** | Tests appear in VS Code's native Testing sidebar (beaker icon) with Run/Debug profiles |
| **Boundary Generator** | `SilverScript: Generate Boundary Tests` command auto-creates zeros/ones/negative/large/mixed test cases |
| **Type-aware Defaults** | New tests are pre-filled based on parameter types (`int→0`, `pubkey→32-byte hex`, `sig→65-byte hex`, etc.) |

---

### Walkthrough

#### Rust: `debugger-dap` crate (new)

- adapter.rs — **754 lines.** The core DAP adapter. Handles `Initialize`, `Launch`, `SetBreakpoints`, `ConfigurationDone`, `Threads`, `StackTrace`, `Scopes`, `Variables`, `Next`, `StepIn`, `StepOut`, `Continue`, `Disconnect`. The `build_runtime()` function branches on whether the launch config specifies a `testFile` (sidecar mode) or direct `scriptPath` (manual mode). The `build_session_with_tx()` function constructs full transaction context — building inputs, outputs, UTXO entries, covenants, signature scripts — using `Box::leak` for the `'static` lifetime required by the script engine.

- launch_config.rs — Deserializes DAP launch arguments into `LaunchConfig`. Supports `scriptPath`, `testFile`/`testName`, `function`, `constructorArgs`, `args`, `scenarioPath`, `stopOnEntry`. Handles `camelCase` ↔ `snake_case` mapping via serde. Includes `Value → String` conversion for mixed JSON arg types.

- refs.rs — Variable reference allocator for DAP scopes (Locals, Stack, Constants). Reset on each stop event.

- main.rs — Stdin/stdout DAP transport loop.

- tests — **3 integration tests** using a test harness that spawns a DAP session in-process: `launch_stops_on_entry_and_disconnects`, `breakpoint_snaps_and_continue_stops`, `continue_hits_breakpoint_in_second_entrypoint`.

#### Rust: `debugger-session` crate (extended)

- test_runner.rs — **241 lines (new).** Sidecar file parser. Deserializes `*.test.json` into `ContractTestFile` → resolves to `ContractTestCaseResolved` with string args. Handles tx scenario resolution (inputs/outputs with optional covenant IDs, constructor args, script overrides). Infers script path from sidecar filename convention.

- args.rs — **130 lines (new).** Shared arg-parsing utilities extracted from the CLI: `parse_ctor_args()`, `parse_call_args()`, `parse_hex_bytes()`. Converts string representations to typed `Expr` values for the compiler.

- session.rs — Extended with `ShadowTxContext` struct for transaction-aware debugging, `with_shadow_tx_context()` builder, shadow expression evaluation that uses the real transaction for covenant opcodes, `call_stack()` for stack traces, `current_function_name()`, `add_breakpoint_resolved()` for line-snapping breakpoints.

#### VS Code Extension (rewritten)

- contractModel.ts — **135 lines (new).** Shared foundation module. Exports: types (`ContractModel`, `SidecarTestCase`, `SidecarTestFile`), path helpers (`inferSidecarPath`, `inferScriptPath`), contract parsing (`parseContractModel` — regex-based extraction of constructor params + entrypoint signatures), type-aware defaults (`defaultForType` — maps SilverScript types to sensible zero values), sidecar I/O (`readSidecar`, `writeSidecar`).

- codeLens.ts — **269 lines (new).** CodeLens provider that renders `▶ Run | 🐛 Debug | ✚ Test | 🧪 N tests` above every `entrypoint function`. **Run** launches a DAP session with type-aware defaults in `noDebug` mode, tracks the session via an adapter tracker, and shows a `✓ passed` / `✗ failed` notification. **Debug** launches with `stopOnEntry: true`. **Test** creates a new sidecar entry pre-filled from the function signature.

- testController.ts — **406 lines (new).** VS Code native `TestController` integration. Discovers `*.test.json` files via workspace glob + `FileSystemWatcher`. Creates test items per sidecar file → per test case. **Run profile** executes tests silently via DAP (launches in `noDebug` mode, tracks `stopped/exception` events for pass/fail). **Debug profile** launches with breakpoints. **Boundary test generator** (`silverscript.tests.generate` command) creates zeros/ones/negative/large/mixed test cases from the function signature, deduplicates against existing tests.

- debug.ts — **212 lines (rewritten from 383).** Clean adapter factory + config provider. Handles `${file}` expansion, test-file flow (picks test name via QuickPick), direct script flow (prompts for constructor args/function/args). Removed: 170+ lines of duplicated helpers, the `debugTestCase` command, `pickTestFile`, `startDebugFromTestFile`, `workspaceFolderForUri`, `parseArgsInputAllowEmpty` — all superseded by the TestController and CodeLens.

- **Deleted**: testPanel.ts (762 lines — TreeDataProvider), testEditorView.ts (572 lines — WebviewViewProvider). These custom sidebar panels are fully replaced by the native Testing API + CodeLens.

#### Extension Manifest

- package.json — Simplified from 342 to 220 lines. Removed: 10 panel commands, 2 sidebar views, 12 menu contributions. Added: `silverscript.tests.generate` command. Kept: DAP debugger config (`testFile`/`testName`/`scriptPath`/`function`/`constructorArgs`/`args`/`stopOnEntry`), 3 initial configurations, all language/breakpoint config.

#### Supporting Files

- int_to_byte.test.json — Example sidecar with 2 tests (`main_valid`, `main_negative_b`) for the `DebugPoC` contract.

- int_to_byte.sil — Updated demo contract (`DebugPoC`) with `bump`, `check_pair`, and `main` entrypoint.

- launch.json — 3 clean configs: Extension Host, Debug Contract, Debug Test.

---

### Test Results

| Suite | Count | Status |
|-------|-------|--------|
| `debugger-session` | 28 | All pass |
| `debugger-dap` | 3 | All pass |
| TypeScript (tsc) | — | 0 errors |
| ESLint | — | 0 warnings |
| esbuild | — | Clean bundle |

---

### Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│  VS Code Extension                                  │
│                                                     │
│  codeLens.ts ──→ ▶ Run | 🐛 Debug | ✚ Test         │
│  testController.ts ──→ Testing Sidebar (beaker)     │
│  debug.ts ──→ DAP Config Provider + Adapter Factory │
│  contractModel.ts ──→ Shared types, parsing, I/O    │
│                                                     │
│           ↕ DAP Protocol (stdin/stdout)              │
├─────────────────────────────────────────────────────┤
│  debugger-dap (Rust binary)                         │
│                                                     │
│  adapter.rs ──→ Launch, Step, Variables, Breakpoints│
│  launch_config.rs ──→ Config deserialization         │
│  refs.rs ──→ Variable reference tracking             │
│                                                     │
│           ↕ Uses                                     │
├─────────────────────────────────────────────────────┤
│  debugger-session (Rust library)                    │
│                                                     │
│  session.rs ──→ Script engine wrapper + debug state │
│  test_runner.rs ──→ Sidecar *.test.json parser      │
│  args.rs ──→ Type-safe arg parsing                  │
│  presentation.rs ──→ Value formatting               │
│                                                     │
│           ↕ Uses                                     │
├─────────────────────────────────────────────────────┤
│  silverscript-lang + kaspa-txscript                 │
│  (Compiler, AST, Script Engine)                     │
└─────────────────────────────────────────────────────┘

  *.sil  ←──→  *.test.json  (sidecar convention)
```