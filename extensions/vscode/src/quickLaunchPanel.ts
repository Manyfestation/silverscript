import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import * as childProcess from "child_process";
import {
  parseContractModel,
  defaultsFromParams,
  defaultForType,
  inferSidecarPath,
  readSidecar,
  writeSidecar,
  ContractModel,
  ContractParam,
  SidecarTestCase,
} from "./contractModel";

// ── Panel singleton ────────────────────────────────────────────────

let panel: vscode.WebviewPanel | undefined;
let activeScriptUri: vscode.Uri | undefined;

type TxInputMsg = {
  utxo_value: number;
  constructor_args?: string[];
  utxo_script_hex?: string;
};
type TxOutputMsg = {
  value: number;
  constructor_args?: string[];
  script_hex?: string;
  p2pk_pubkey?: string;
};
type TxMsg = {
  active_input_index: number;
  inputs: TxInputMsg[];
  outputs: TxOutputMsg[];
};

type PanelMessage =
  | {
      kind: "debug" | "run" | "save" | "runAllTests";
      constructorArgs: string[];
      function: string;
      args: string[];
      tx: TxMsg;
    }
  | { kind: "generateKey" };

async function openPanel(
  ctx: vscode.ExtensionContext,
  uri?: vscode.Uri,
  initialFunction?: string,
): Promise<void> {
  const scriptUri =
    uri ??
    (vscode.window.activeTextEditor?.document.languageId ===
    "silverscript"
      ? vscode.window.activeTextEditor.document.uri
      : undefined);

  if (!scriptUri) {
    vscode.window.showErrorMessage(
      "Open a .sil file first.",
    );
    return;
  }

  const source = fs.readFileSync(scriptUri.fsPath, "utf8");
  const model = parseContractModel(source);
  activeScriptUri = scriptUri;

  if (panel) {
    panel.reveal(vscode.ViewColumn.Beside);
  } else {
    panel = vscode.window.createWebviewPanel(
      "silverscriptLaunch",
      model.name,
      vscode.ViewColumn.Beside,
      { enableScripts: true, retainContextWhenHidden: true },
    );
    panel.webview.onDidReceiveMessage(async (msg: PanelMessage) => {
      if (msg.kind === "generateKey") {
        const root = path.resolve(ctx.extensionPath, "..", "..");
        const bin = path.join(
          root, "target", "debug",
          process.platform === "win32" ? "debugger-dap.exe" : "debugger-dap",
        );
        try {
          const stdout = childProcess.execFileSync(bin, ["--keygen"], { encoding: "utf8" });
          const parsed = JSON.parse(stdout);
          panel!.webview.postMessage({ kind: "keyGenerated", ...parsed });
        } catch (e: any) {
          vscode.window.showErrorMessage(`Keygen failed: ${e.message}`);
        }
        return;
      }
      if (!activeScriptUri) {return;}

      const config: vscode.DebugConfiguration = {
        type: "silverscript",
        request: "launch",
        name: `SilverScript: ${msg.function}`,
        scriptPath: activeScriptUri.fsPath,
        function: msg.function,
        constructorArgs: msg.constructorArgs,
        args: msg.args,
        tx: msg.tx,
        stopOnEntry: msg.kind === "debug",
        _silverscriptQuickRun: msg.kind === "run",
      };
      const folder =
        vscode.workspace.getWorkspaceFolder(activeScriptUri) ??
        vscode.workspace.workspaceFolders?.[0];

      if (msg.kind === "debug") {
        await vscode.debug.startDebugging(folder, config);
      } else if (msg.kind === "run") {
        await vscode.debug.startDebugging(folder, config, {
          noDebug: true,
        });
      } else if (msg.kind === "save") {
        const sp = inferSidecarPath(activeScriptUri.fsPath);
        const sidecar = await readSidecar(sp);
        const tests = sidecar.tests ?? [];
        const n = tests.filter(
          (t) => t.function === msg.function,
        ).length;
        const tc: SidecarTestCase = {
          name: `${msg.function}_case_${n}`,
          function: msg.function,
          constructor_args: msg.constructorArgs,
          args: msg.args,
          expect: "pass",
          tx: msg.tx,
        };
        await writeSidecar(sp, { tests: [...tests, tc] });
        vscode.window.showInformationMessage(
          `Saved test ${tc.name} → ${path.basename(sp)} (append to tests[])`,
        );
      } else if (msg.kind === "runAllTests") {
        await vscode.commands.executeCommand("testing.runAll");
      }
    });
    panel.onDidDispose(() => {
      panel = undefined;
      activeScriptUri = undefined;
    });
  }

  panel.title = model.name;
  panel.webview.html = buildHtml(
    model,
    scriptUri.fsPath,
    initialFunction,
  );
}

// ── HTML builder ───────────────────────────────────────────────────

function fieldRows(
  group: string,
  params: ContractParam[],
): string {
  if (!params.length) {
    return `<p class="dim">No parameters</p>`;
  }
  const cryptoTypes = ["pubkey", "sig", "datasig", "bytes20", "bytes32", "byte[20]", "byte[32]"];
  return params
    .map((p, i) => {
      const val = String(defaultForType(p.type));
      const isCrypto = cryptoTypes.includes(p.type);
      const keyBtn = isCrypto
        ? ` <button class="key-btn" data-group="${group}" data-idx="${i}" data-type="${p.type}" title="Fill from Key Wallet">🔑</button>`
        : "";
      const cryptoClass = isCrypto ? " crypto-input" : "";
      const dataType = isCrypto ? ` data-type="${p.type}"` : "";
      return `
      <label>${p.name} <span class="type">${p.type}</span></label>
      <div class="field-row">
        <input class="field${cryptoClass}"
               data-group="${group}" data-idx="${i}"${dataType}
               value="${escHtml(val)}"
               placeholder="${p.type}" />${keyBtn}
      </div>`;
    })
    .join("\n");
}

function escHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function buildHtml(
  model: ContractModel,
  scriptPath: string,
  initialFunction?: string,
): string {
  const selectedFn =
    (initialFunction &&
    model.entrypoints.some((ep) => ep.name === initialFunction)
      ? initialFunction
      : model.entrypoints[0]?.name) ?? "";

  const fnOptions = model.entrypoints
    .map(
      (ep, i) =>
        `<option value="${ep.name}" ${ep.name === selectedFn || (!selectedFn && i === 0) ? "selected" : ""}>${ep.name}(${ep.params.map((p) => `${p.type} ${p.name}`).join(", ")})</option>`,
    )
    .join("\n");

  // Pre-build param groups for each entrypoint
  const epMap: Record<string, string> = {};
  for (const ep of model.entrypoints) {
    epMap[ep.name] = fieldRows("args", ep.params);
  }

  return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<style>
  :root {
    --bg: var(--vscode-editor-background);
    --fg: var(--vscode-editor-foreground);
    --input-bg: var(--vscode-input-background);
    --input-fg: var(--vscode-input-foreground);
    --input-border: var(--vscode-input-border, transparent);
    --btn: var(--vscode-button-background);
    --btn-fg: var(--vscode-button-foreground);
    --btn-hover: var(--vscode-button-hoverBackground);
    --badge: var(--vscode-badge-background);
    --badge-fg: var(--vscode-badge-foreground);
    --focus: var(--vscode-focusBorder);
    --sep: var(--vscode-widget-border, rgba(128,128,128,.2));
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font: 13px/1.5 var(--vscode-font-family, system-ui, sans-serif);
    color: var(--fg); background: var(--bg);
    padding: 16px 20px;
  }
  h1 { font-size: 16px; font-weight: 600; margin-bottom: 4px; }
  .path { font-size: 11px; opacity: .55; margin-bottom: 16px;
           white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  section { margin-bottom: 16px; }
  section h2 {
    font-size: 11px; text-transform: uppercase; letter-spacing: .06em;
    opacity: .6; margin-bottom: 6px;
  }
  label { display: block; font-size: 12px; margin: 6px 0 2px; }
  .type {
    font-size: 10px; padding: 1px 5px; border-radius: 3px;
    background: var(--badge); color: var(--badge-fg);
    margin-left: 4px; vertical-align: middle;
  }
  input, select {
    width: 100%; padding: 5px 8px; font-size: 13px;
    background: var(--input-bg); color: var(--input-fg);
    border: 1px solid var(--input-border); border-radius: 3px;
    outline: none; font-family: var(--vscode-editor-font-family, monospace);
  }
  input:focus, select:focus { border-color: var(--focus); }
  select { cursor: pointer; }
  .dim { font-size: 12px; opacity: .4; font-style: italic; }
  .help {
    font-size: 11px;
    opacity: .75;
    margin-top: 8px;
  }
  hr { border: none; border-top: 1px solid var(--sep); margin: 16px 0; }
  .actions-secondary {
    display: flex;
    gap: 8px;
    margin-top: 8px;
  }
  .actions-primary {
    display: flex;
    gap: 8px;
    margin-top: 12px;
  }
  button {
    flex: 1; padding: 7px 0; border: none; border-radius: 4px;
    font-size: 13px; font-weight: 500; cursor: pointer;
    background: var(--btn); color: var(--btn-fg);
    transition: background .15s;
  }
  button:hover { background: var(--btn-hover); }
  button.primary {
    padding: 10px 0;
    font-size: 14px;
    font-weight: 600;
  }
  button.secondary {
    background: transparent;
    border: 1px solid var(--sep);
    color: var(--fg);
    font-size: 12px;
    font-weight: 500;
    opacity: .9;
  }
  button.secondary:hover { background: rgba(128,128,128,.1); }

  /* Field row with key button */
  .field-row { display: flex; align-items: center; gap: 4px; position: relative; }
  .field-row input.field { flex: 1; }
  .field-row input.field.crypto-input { cursor: pointer; }

  /* Key wallet */
  .key-wallet summary {
    cursor: pointer; font-size: 12px; font-weight: 600;
    opacity: .8; user-select: none; padding: 4px 0;
  }
  .key-wallet summary:hover { opacity: 1; }
  .key-wallet .key-list { margin: 6px 0; }
  .key-wallet .key-row {
    display: flex; align-items: center; gap: 6px;
    font-size: 12px; font-family: var(--vscode-editor-font-family, monospace);
    padding: 2px 0;
  }
  .key-wallet .key-name { font-weight: 600; min-width: 48px; }
  .key-wallet .key-hash { opacity: .6; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .key-wallet .key-del {
    background: none; border: none; color: var(--fg); opacity: .5;
    cursor: pointer; font-size: 14px; padding: 0 4px; flex: none;
  }
  .key-wallet .key-del:hover { opacity: 1; }
  .key-wallet .key-gen {
    margin-top: 4px; padding: 4px 10px; font-size: 11px;
    flex: none; width: auto;
  }

  /* Key button on inputs */
  .key-btn {
    flex: none; width: 26px; height: 26px; padding: 0;
    font-size: 14px; line-height: 26px; text-align: center;
    background: transparent; border: 1px solid var(--sep);
    border-radius: 3px; cursor: pointer; color: var(--fg);
  }
  .key-btn:hover { background: rgba(128,128,128,.15); }

  /* Key dropdown — positioned relative to .field-row */
  .key-dropdown {
    position: absolute; z-index: 100;
    top: calc(100% + 4px); left: 0; right: 0;
    background: var(--vscode-editorWidget-background, var(--input-bg));
    border: 1px solid var(--vscode-editorWidget-border, var(--sep));
    border-radius: 6px;
    box-shadow: 0 4px 12px rgba(0,0,0,.35);
    max-height: 180px; overflow-y: auto;
    font-size: 12px;
    padding: 4px 0;
  }
  .key-dropdown .kd-item {
    padding: 6px 10px; cursor: pointer;
    white-space: nowrap;
    display: flex; align-items: center; gap: 8px;
    border-radius: 3px; margin: 0 4px;
  }
  .key-dropdown .kd-item:hover { background: var(--btn); color: var(--btn-fg); }
  .key-dropdown .kd-name { font-weight: 600; }
  .key-dropdown .kd-hash { opacity: .5; font-size: 11px; overflow: hidden; text-overflow: ellipsis; }
  .key-dropdown .kd-sep { border-top: 1px solid var(--sep); margin: 4px 0; }
  .key-dropdown .kd-action { opacity: .7; font-style: italic; }

  /* TX context section */
  .tx-section summary {
    cursor: pointer; font-size: 12px; font-weight: 600;
    opacity: .8; user-select: none; padding: 4px 0;
    text-transform: uppercase; letter-spacing: .06em;
  }
  .tx-section summary:hover { opacity: 1; }
  .tx-subsection { margin: 10px 0 6px; }
  .tx-subsection h3 {
    font-size: 11px; text-transform: uppercase; letter-spacing: .06em;
    opacity: .6; margin-bottom: 4px;
  }
  .tx-card {
    border: 1px solid var(--sep); border-radius: 6px;
    padding: 8px 10px; margin-bottom: 8px;
    background: rgba(128,128,128,.04);
  }
  .tx-card-header {
    display: flex; align-items: center; gap: 6px;
    font-size: 12px; font-weight: 600; margin-bottom: 6px;
  }
  .tx-card-header .tx-badge {
    font-size: 9px; padding: 1px 5px; border-radius: 3px;
    background: var(--badge); color: var(--badge-fg);
    text-transform: uppercase; letter-spacing: .04em;
    cursor: pointer;
  }
  .tx-card-header .tx-badge.active {
    background: var(--btn); color: var(--btn-fg);
  }
  .tx-card-header .spacer { flex: 1; }
  .tx-card-header .tx-del {
    background: none; border: none; color: var(--fg); opacity: .4;
    cursor: pointer; font-size: 16px; padding: 0 2px; flex: none;
  }
  .tx-card-header .tx-del:hover { opacity: 1; }
  .tx-card label { font-size: 11px; margin: 4px 0 1px; }
  .tx-card input, .tx-card select { font-size: 12px; padding: 3px 6px; }
  .tx-state-fields { margin-top: 4px; padding-left: 8px; border-left: 2px solid var(--sep); }
  .tx-state-fields label { font-size: 10px; }
  .tx-state-fields input { font-size: 11px; padding: 2px 5px; }
  .tx-add {
    flex: none; width: auto; padding: 3px 10px; font-size: 11px;
    background: transparent; border: 1px dashed var(--sep);
    color: var(--fg); opacity: .6; margin-bottom: 8px;
  }
  .tx-add:hover { opacity: 1; background: rgba(128,128,128,.06); }
</style>
</head>
<body>

<h1>${escHtml(model.name)}</h1>
<div class="path">${escHtml(scriptPath)}</div>

<section>
  <h2>Constructor</h2>
  <div id="ctor-fields">
    ${fieldRows("ctor", model.constructorParams)}
  </div>
</section>

<hr/>

<section>
  <h2>Entrypoint</h2>
  <select id="fn-select">
    ${fnOptions}
  </select>
</section>

<section>
  <h2>Function Arguments</h2>
  <div id="args-fields">
    ${selectedFn && epMap[selectedFn] ? epMap[selectedFn] : '<p class="dim">No entrypoints</p>'}
  </div>
</section>

<hr/>

<details class="tx-section" id="tx-section" open>
  <summary>Transaction Context</summary>

  <div class="tx-subsection">
    <h3>Inputs</h3>
    <div id="tx-inputs"></div>
    <button class="tx-add" id="btn-add-input">+ Add Input</button>
  </div>

  <div class="tx-subsection">
    <h3>Outputs</h3>
    <div id="tx-outputs"></div>
    <button class="tx-add" id="btn-add-output">+ Add Output</button>
  </div>
</details>

<hr/>

<div class="actions-primary">
  <button id="btn-run" class="primary">Run</button>
  <button id="btn-debug" class="primary">Debug</button>
</div>

<div class="actions-secondary">
  <button id="btn-save" class="secondary">Save Test</button>
  <button id="btn-run-all" class="secondary">Run All Tests</button>
</div>

<hr/>

<details class="key-wallet" id="key-wallet">
  <summary>Keys</summary>
  <div class="key-list" id="key-list"></div>
  <button class="key-gen" id="btn-keygen">Generate Keypair</button>
</details>

<script>
  const vscode = acquireVsCodeApi();
  const epMap = ${JSON.stringify(epMap)};
  const ctorParams = ${JSON.stringify(model.constructorParams)};

  const fnSelect = document.getElementById('fn-select');
  const argsDiv  = document.getElementById('args-fields');

  fnSelect.addEventListener('change', () => {
    argsDiv.innerHTML = epMap[fnSelect.value] || '<p class="dim">No parameters</p>';
  });

  function collect(group) {
    return [...document.querySelectorAll('input.field[data-group="' + group + '"]')]
      .map(el => el.value);
  }

  // ── TX Context State ───────────────────────────────────────────
  let txInputs = [{ value: 5000, scriptType: 'self', ctorArgs: [], hexScript: '' }];
  let txOutputs = [{ value: 5000, scriptType: 'self', ctorArgs: [], hexScript: '', pubkey: '' }];
  let activeInputIndex = 0;

  function renderCtorFields(prefix, values) {
    if (!ctorParams.length) return '';
    return ctorParams.map((p, i) => {
      const val = values[i] || '';
      return '<label>' + p.name + ' <span class="type">' + p.type + '</span></label>' +
        '<input class="tx-ctor-val" data-prefix="' + prefix + '" data-idx="' + i + '" ' +
        'value="' + val.replace(/"/g, '&quot;') + '" placeholder="' + p.type + '" />';
    }).join('');
  }

  function renderTxInputs() {
    const el = document.getElementById('tx-inputs');
    el.innerHTML = txInputs.map((inp, i) => {
      const isActive = i === activeInputIndex;
      const badge = isActive
        ? '<span class="tx-badge active" data-ti="' + i + '">active</span>'
        : '<span class="tx-badge" data-ti="' + i + '" title="Click to set as active input">set active</span>';
      const stateFields = inp.scriptType === 'custom-state'
        ? '<div class="tx-state-fields">' + renderCtorFields('ti-' + i, inp.ctorArgs) + '</div>' : '';
      const hexField = inp.scriptType === 'custom-hex'
        ? '<label>UTXO Script (hex)</label><input class="tx-hex-val" data-kind="input" data-ti="' + i + '" value="' + (inp.hexScript || '').replace(/"/g, '&quot;') + '" placeholder="0x..." />' : '';
      return '<div class="tx-card" data-ti="' + i + '">' +
        '<div class="tx-card-header">' +
          '<span>Input #' + i + '</span>' + badge +
          '<span class="spacer"></span>' +
          (txInputs.length > 1 ? '<button class="tx-del" data-kind="input" data-ti="' + i + '">&times;</button>' : '') +
        '</div>' +
        '<label>Value <span class="type">sompi</span></label>' +
        '<input type="number" class="tx-value" data-kind="input" data-ti="' + i + '" value="' + inp.value + '" />' +
        '<label>Script</label>' +
        '<select class="tx-script-type" data-kind="input" data-ti="' + i + '">' +
          '<option value="self"' + (inp.scriptType === 'self' ? ' selected' : '') + '>This contract (same state)</option>' +
          (ctorParams.length ? '<option value="custom-state"' + (inp.scriptType === 'custom-state' ? ' selected' : '') + '>This contract (custom state)</option>' : '') +
          '<option value="custom-hex"' + (inp.scriptType === 'custom-hex' ? ' selected' : '') + '>Custom script (hex)</option>' +
        '</select>' +
        stateFields + hexField +
      '</div>';
    }).join('');
  }

  function renderTxOutputs() {
    const el = document.getElementById('tx-outputs');
    el.innerHTML = txOutputs.map((out, i) => {
      const stateFields = out.scriptType === 'custom-state'
        ? '<div class="tx-state-fields">' + renderCtorFields('to-' + i, out.ctorArgs) + '</div>' : '';
      const hexField = out.scriptType === 'custom-hex'
        ? '<label>Script (hex)</label><input class="tx-hex-val" data-kind="output" data-ti="' + i + '" value="' + (out.hexScript || '').replace(/"/g, '&quot;') + '" placeholder="0x..." />' : '';
      const p2pkField = out.scriptType === 'p2pk'
        ? '<label>Public Key <span class="type">hex</span></label>' +
          '<div class="field-row">' +
            '<input class="tx-p2pk-val crypto-input" data-kind="output" data-ti="' + i + '" data-type="pubkey" value="' + (out.pubkey || '').replace(/"/g, '&quot;') + '" placeholder="pubkey hex" />' +
            ' <button class="key-btn" data-kind="output" data-ti="' + i + '" data-type="pubkey" data-p2pk="1" title="Fill from Key Wallet">&#128273;</button>' +
          '</div>' : '';
      return '<div class="tx-card" data-ti="' + i + '">' +
        '<div class="tx-card-header">' +
          '<span>Output #' + i + '</span>' +
          '<span class="spacer"></span>' +
          (txOutputs.length > 1 ? '<button class="tx-del" data-kind="output" data-ti="' + i + '">&times;</button>' : '') +
        '</div>' +
        '<label>Value <span class="type">sompi</span></label>' +
        '<input type="number" class="tx-value" data-kind="output" data-ti="' + i + '" value="' + out.value + '" />' +
        '<label>Destination</label>' +
        '<select class="tx-script-type" data-kind="output" data-ti="' + i + '">' +
          '<option value="self"' + (out.scriptType === 'self' ? ' selected' : '') + '>This contract (same state)</option>' +
          (ctorParams.length ? '<option value="custom-state"' + (out.scriptType === 'custom-state' ? ' selected' : '') + '>This contract (custom state)</option>' : '') +
          '<option value="p2pk"' + (out.scriptType === 'p2pk' ? ' selected' : '') + '>P2PK (pay to pubkey)</option>' +
          '<option value="custom-hex"' + (out.scriptType === 'custom-hex' ? ' selected' : '') + '>Custom script (hex)</option>' +
        '</select>' +
        stateFields + p2pkField + hexField +
      '</div>';
    }).join('');
  }

  // Delegate events for tx cards
  document.addEventListener('change', (e) => {
    const sel = e.target.closest('.tx-script-type');
    if (sel) {
      const kind = sel.dataset.kind;
      const idx = Number(sel.dataset.ti);
      const arr = kind === 'input' ? txInputs : txOutputs;
      arr[idx].scriptType = sel.value;
      arr[idx].ctorArgs = [];
      arr[idx].hexScript = '';
      if (arr[idx].pubkey !== undefined) arr[idx].pubkey = '';
      kind === 'input' ? renderTxInputs() : renderTxOutputs();
    }
    const val = e.target.closest('.tx-value');
    if (val) {
      const kind = val.dataset.kind;
      const idx = Number(val.dataset.ti);
      const arr = kind === 'input' ? txInputs : txOutputs;
      arr[idx].value = Number(val.value) || 0;
    }
  });

  document.addEventListener('input', (e) => {
    const ctor = e.target.closest('.tx-ctor-val');
    if (ctor) {
      const prefix = ctor.dataset.prefix;
      const idx = Number(ctor.dataset.idx);
      const m = prefix.match(/^(ti|to)-(\d+)$/);
      if (m) {
        const arr = m[1] === 'ti' ? txInputs : txOutputs;
        const cardIdx = Number(m[2]);
        if (!arr[cardIdx].ctorArgs) arr[cardIdx].ctorArgs = [];
        arr[cardIdx].ctorArgs[idx] = ctor.value;
      }
    }
    const p2pk = e.target.closest('.tx-p2pk-val');
    if (p2pk) {
      const idx = Number(p2pk.dataset.ti);
      txOutputs[idx].pubkey = p2pk.value;
    }
    const hex = e.target.closest('.tx-hex-val');
    if (hex) {
      const kind = hex.dataset.kind;
      const idx = Number(hex.dataset.ti);
      const arr = kind === 'input' ? txInputs : txOutputs;
      arr[idx].hexScript = hex.value;
    }
  });

  document.addEventListener('click', (e) => {
    const del = e.target.closest('.tx-del');
    if (del) {
      const kind = del.dataset.kind;
      const idx = Number(del.dataset.ti);
      if (kind === 'input') {
        txInputs.splice(idx, 1);
        if (activeInputIndex >= txInputs.length) activeInputIndex = txInputs.length - 1;
        if (activeInputIndex === idx) activeInputIndex = 0;
        renderTxInputs();
      } else {
        txOutputs.splice(idx, 1);
        renderTxOutputs();
      }
    }
    const badge = e.target.closest('.tx-badge');
    if (badge && badge.dataset.ti !== undefined) {
      activeInputIndex = Number(badge.dataset.ti);
      renderTxInputs();
    }
  });

  document.getElementById('btn-add-input').addEventListener('click', () => {
    txInputs.push({ value: 5000, scriptType: 'self', ctorArgs: [], hexScript: '' });
    renderTxInputs();
  });
  document.getElementById('btn-add-output').addEventListener('click', () => {
    txOutputs.push({ value: 5000, scriptType: 'self', ctorArgs: [], hexScript: '', pubkey: '' });
    renderTxOutputs();
  });

  renderTxInputs();
  renderTxOutputs();

  function collectTx() {
    return {
      active_input_index: activeInputIndex,
      inputs: txInputs.map(inp => {
        const o = { utxo_value: inp.value };
        if (inp.scriptType === 'custom-state' && inp.ctorArgs.length) o.constructor_args = inp.ctorArgs;
        if (inp.scriptType === 'custom-hex' && inp.hexScript) o.utxo_script_hex = inp.hexScript;
        return o;
      }),
      outputs: txOutputs.map(out => {
        const o = { value: out.value };
        if (out.scriptType === 'custom-state' && out.ctorArgs.length) o.constructor_args = out.ctorArgs;
        if (out.scriptType === 'p2pk' && out.pubkey) o.p2pk_pubkey = out.pubkey;
        if (out.scriptType === 'custom-hex' && out.hexScript) o.script_hex = out.hexScript;
        return o;
      }),
    };
  }

  function send(kind) {
    vscode.postMessage({
      kind,
      constructorArgs: collect('ctor'),
      function: fnSelect.value,
      args: collect('args'),
      tx: collectTx(),
    });
  }

  document.getElementById('btn-save').addEventListener('click',  () => send('save'));
  document.getElementById('btn-run-all').addEventListener('click',  () => send('runAllTests'));
  document.getElementById('btn-run').addEventListener('click',   () => send('run'));
  document.getElementById('btn-debug').addEventListener('click', () => send('debug'));

  // ── Key Wallet ──────────────────────────────────────────────────
  let keys = [];
  let keyCounter = 0;
  let pendingFill = null; // { input, type }

  function valueForType(key, type) {
    switch (type) {
      case 'pubkey':  return key.pubkey;
      case 'sig':
      case 'datasig': return key.secret_key;
      case 'bytes20':
      case 'byte[20]': return '0x' + (key.pkh || '').replace(/^0x/i, '').slice(0, 40);
      case 'bytes32':
      case 'byte[32]': return key.pkh;
      default:        return key.pubkey;
    }
  }

  function renderKeyList() {
    const el = document.getElementById('key-list');
    if (!keys.length) { el.innerHTML = ''; return; }
    el.innerHTML = keys.map((k, i) =>
      '<div class="key-row">' +
        '<span class="key-name">' + k.name + '</span>' +
        '<span class="key-hash">' + k.pubkey + '</span>' +
        '<button class="key-del" data-ki="' + i + '">&times;</button>' +
      '</div>'
    ).join('');
    el.querySelectorAll('.key-del').forEach(b => {
      b.addEventListener('click', () => {
        keys.splice(Number(b.dataset.ki), 1);
        renderKeyList();
      });
    });
  }

  document.getElementById('btn-keygen').addEventListener('click', () => {
    vscode.postMessage({ kind: 'generateKey' });
  });

  // Close any open dropdown on outside click
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.key-dropdown') && !e.target.closest('.key-btn') && !e.target.closest('.crypto-input')) {
      document.querySelectorAll('.key-dropdown').forEach(d => d.remove());
    }
  });

  function showDropdown(fieldRow, input, type) {
    // Remove existing dropdowns
    document.querySelectorAll('.key-dropdown').forEach(d => d.remove());

    const dd = document.createElement('div');
    dd.className = 'key-dropdown';

    keys.forEach((k, i) => {
      const item = document.createElement('div');
      item.className = 'kd-item';
      item.innerHTML = '<span class="kd-name">' + k.name + '</span><span class="kd-hash">' + k.pubkey.slice(0, 14) + '…</span>';
      item.addEventListener('click', () => {
        input.value = valueForType(k, type);
        input.dispatchEvent(new Event('input'));
        dd.remove();
      });
      dd.appendChild(item);
    });

    if (keys.length) {
      const sep = document.createElement('div');
      sep.className = 'kd-sep';
      dd.appendChild(sep);
    }

    const gen = document.createElement('div');
    gen.className = 'kd-item kd-action';
    gen.textContent = '+ Generate new';
    gen.addEventListener('click', () => {
      pendingFill = { input, type };
      vscode.postMessage({ kind: 'generateKey' });
      dd.remove();
    });
    dd.appendChild(gen);

    fieldRow.appendChild(dd);
  }

  // Delegate key-btn clicks (works after innerHTML swap)
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.key-btn');
    if (!btn) return;
    e.stopPropagation();
    const type = btn.dataset.type;
    const fieldRow = btn.closest('.field-row');
    const input = fieldRow.querySelector('input.field') || fieldRow.querySelector('input');
    showDropdown(fieldRow, input, type);
  });

  // Clicking the crypto input itself also shows the dropdown
  document.addEventListener('click', (e) => {
    const input = e.target.closest('input.crypto-input');
    if (!input) return;
    e.stopPropagation();
    const type = input.dataset.type;
    const fieldRow = input.closest('.field-row');
    showDropdown(fieldRow, input, type);
  });

  // Auto-fill all empty/default crypto inputs with the appropriate value from a key
  function autoFillEmpty(key) {
    document.querySelectorAll('input.crypto-input').forEach(inp => {
      // Skip if user has already set a non-default value
      const v = (inp.value || '').replace(/^0x/i, '');
      if (v && !/^0+$/.test(v)) return;
      const fill = valueForType(key, inp.dataset.type);
      if (fill) {
        inp.value = fill;
        inp.dispatchEvent(new Event('input'));
      }
    });
  }

  // Handle keyGenerated from extension host
  window.addEventListener('message', (e) => {
    const msg = e.data;
    if (msg.kind === 'keyGenerated') {
      const key = {
        name: 'key_' + (++keyCounter),
        pubkey: msg.pubkey,
        secret_key: msg.secret_key,
        pkh: msg.pkh,
      };
      keys.push(key);
      renderKeyList();
      document.getElementById('key-wallet').open = true;

      if (pendingFill) {
        pendingFill.input.value = valueForType(key, pendingFill.type);
        pendingFill.input.dispatchEvent(new Event('input'));
        pendingFill = null;
      }

      // Auto-fill all empty/default crypto fields
      autoFillEmpty(key);
    }
  });
</script>

</body>
</html>`;
}

// ── Registration ───────────────────────────────────────────────────

export function registerSilverScriptQuickLaunchPanel(
  ctx: vscode.ExtensionContext,
): void {
  ctx.subscriptions.push(
    vscode.commands.registerCommand(
      "silverscript.debug.configureLaunch",
      (uri?: vscode.Uri, initialFunction?: string) =>
        openPanel(ctx, uri, initialFunction),
    ),
  );
}
