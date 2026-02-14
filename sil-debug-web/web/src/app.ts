/* global window, document, fetch, navigator */

const $ = (id) => document.getElementById(id);

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function clamp(n, lo, hi) {
  return Math.max(lo, Math.min(hi, n));
}

function debounce(fn, ms) {
  let t = null;
  return (...args) => {
    if (t) window.clearTimeout(t);
    t = window.setTimeout(() => fn(...args), ms);
  };
}

function isTextInput(el) {
  if (!el) return false;
  const tag = String(el.tagName || "").toLowerCase();
  return tag === "input" || tag === "textarea" || tag === "select";
}

function clampInt(n, lo, hi) {
  return Math.max(lo, Math.min(hi, Math.round(n)));
}

function hexToBytes(hex) {
  const s = String(hex || "").trim().replace(/^0x/i, "");
  if (s.length === 0) return new Uint8Array();
  const clean = s.length % 2 === 0 ? s : `0${s}`;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesHint(hex) {
  const bytes = hexToBytes(hex);
  const len = bytes.length;
  if (len === 0) return "0 bytes";

  // Avoid heavy work / huge DOM strings for large stack items.
  if (len > 4096) return `${len} bytes`;

  let printable = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126)) printable++;
  }
  const mostlyAscii = printable / len > 0.9;
  if (!mostlyAscii) return `${len} bytes`;

  const previewLimit = 256;
  const n = Math.min(len, previewLimit);
  const chars = new Array(n);
  for (let i = 0; i < n; i++) chars[i] = String.fromCharCode(bytes[i]);
  let s = chars.join("").replaceAll("\n", "\\n").replaceAll("\r", "\\r").replaceAll("\t", "\\t");
  if (len > previewLimit) s += "…";
  return `${len} bytes, ascii "${s}"`;
}

function mappingLabel(mapping) {
  if (!mapping || !mapping.kind) return null;
  if (mapping.kind === "Statement" || mapping.kind.Statement) return "stmt";
  if (mapping.kind === "Virtual" || mapping.kind.Virtual) return "virtual";
  if (mapping.kind.InlineCallEnter) return `enter:${mapping.kind.InlineCallEnter.callee}`;
  if (mapping.kind.InlineCallExit) return `exit:${mapping.kind.InlineCallExit.callee}`;
  if (mapping.kind.Synthetic) return `syn:${mapping.kind.Synthetic.label}`;
  return null;
}

function mappingLine(mapping) {
  return mapping && mapping.span ? mapping.span.line : null;
}

function editorLineMetrics() {
  const editor = $("editor");
  if (!editor) return { lineHeight: 24, paddingTop: 8 };
  const cs = window.getComputedStyle(editor);
  const lineHeight = Number.parseFloat(cs.lineHeight) || 24;
  const paddingTop = Number.parseFloat(cs.paddingTop) || 8;
  return { lineHeight, paddingTop };
}

/* ============ KEY WALLET ============ */

const KEY_STORAGE_KEY = "silverscript_key_wallet";

function loadKeys() {
  try {
    const raw = localStorage.getItem(KEY_STORAGE_KEY);
    if (raw) return JSON.parse(raw);
  } catch (_) { /* ignore */ }
  return [];
}

function saveKeys(keys) {
  localStorage.setItem(KEY_STORAGE_KEY, JSON.stringify(keys));
}

function nextKeyName(keys) {
  let max = 0;
  for (const k of keys) {
    const m = String(k.name).match(/^key(\d+)$/);
    if (m) max = Math.max(max, Number(m[1]));
  }
  return `key${max + 1}`;
}

async function generateKeypair(keys) {
  const resp = await fetch("/api/keygen");
  if (!resp.ok) throw new Error("keygen failed");
  const data = await resp.json();
  const name = nextKeyName(keys);
  return {
    name,
    pubkey: String(data.pubkey || ""),
    sig: String(data.sig || ""),
    pkh: String(data.pkh || ""),
  };
}

function showToast(msg) {
  let toast = document.getElementById("copyToast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "copyToast";
    toast.className = "copy-toast";
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.classList.add("show");
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => toast.classList.remove("show"), 1400);
}

function renderKeyWallet(state) {
  const view = $("keysListView");
  const keys = state.keys;
  $("keysMeta").textContent = keys.length ? `${keys.length}` : "";

  if (!keys.length) {
    view.innerHTML = `<div class="keys-empty">No keys yet. Click <strong>Generate Keypair</strong> to add one.</div>`;
    return;
  }

  const rows = keys.map((k, idx) => {
    const pkShort = String(k.pubkey).slice(0, 12) + "…" + String(k.pubkey).slice(-6);
    const sigShort = String(k.sig).slice(0, 12) + "…" + String(k.sig).slice(-6);
    const pkhVal = String(k.pkh || "");
    const pkhShort = pkhVal.length > 18 ? pkhVal.slice(0, 12) + "…" + pkhVal.slice(-6) : pkhVal || "—";
    return `<div class="key-entry" data-kidx="${idx}">
      <div class="key-entry-header">
        <div class="key-name"><span class="key-dot"></span><span class="key-name-text" data-kidx="${idx}">${escapeHtml(k.name)}</span></div>
        <div class="key-actions">
          <button class="key-rename" data-kidx="${idx}" title="Rename">✏️</button>
          <button class="key-delete" data-kidx="${idx}" title="Delete">✕</button>
        </div>
      </div>
      <div class="key-fields">
        <div class="key-field">
          <span class="key-field-label">pk</span>
          <span class="key-field-value" data-copy="${escapeHtml(k.pubkey)}" title="Click to copy: ${escapeHtml(k.pubkey)}">${escapeHtml(pkShort)}</span>
        </div>
        <div class="key-field">
          <span class="key-field-label">sig</span>
          <span class="key-field-value" data-copy="${escapeHtml(k.sig)}" title="Click to copy: ${escapeHtml(k.sig)}">${escapeHtml(sigShort)}</span>
        </div>
        <div class="key-field">
          <span class="key-field-label">pkh</span>
          <span class="key-field-value" data-copy="${escapeHtml(pkhVal)}" title="Click to copy: ${escapeHtml(pkhVal)}">${escapeHtml(pkhShort)}</span>
        </div>
      </div>
    </div>`;
  });
  view.innerHTML = rows.join("");

  // Copy on click
  view.querySelectorAll(".key-field-value").forEach((el) => {
    el.addEventListener("click", async () => {
      const val = el.dataset.copy || "";
      await navigator.clipboard.writeText(val);
      showToast(`Copied ${val.slice(0, 16)}…`);
    });
  });

  // Delete
  view.querySelectorAll(".key-delete").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.dataset.kidx);
      state.keys.splice(idx, 1);
      saveKeys(state.keys);
      renderKeyWallet(state);
    });
  });

  // Rename (inline)
  view.querySelectorAll(".key-rename").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.dataset.kidx);
      const current = state.keys[idx].name;
      const next = prompt("Rename key:", current);
      if (next && next.trim()) {
        state.keys[idx].name = next.trim();
        saveKeys(state.keys);
        renderKeyWallet(state);
      }
    });
  });
}

/** Check if a type should get a key-gen button */
function isKeyType(typeName) {
  const t = String(typeName || "");
  return t === "pubkey" || t === "sig" || t === "datasig" || t === "bytes20" || t === "bytes32";
}

/** Get the right value from a keypair for a type */
function keyValueForType(kp, typeName) {
  const t = String(typeName || "");
  if (t === "pubkey") return kp.pubkey;
  if (t === "sig" || t === "datasig") return kp.sig;
  if (t === "bytes20" || t === "bytes32") return kp.pkh || "";
  return kp.pubkey;
}

function defaultArgValue(typeName) {
  const t = String(typeName || "");
  if (t.endsWith("[]")) return "[]";
  if (t === "int") return "0";
  if (t === "bool") return "false";
  if (t === "string") return "";
  if (t === "bytes") return "0x";
  if (t === "byte") return "0x00";
  if (t === "pubkey") return `0x${"00".repeat(32)}`;
  if (t === "sig" || t === "datasig") return `0x${"00".repeat(64)}`;
  if (t.startsWith("bytes")) {
    const n = Number(t.slice("bytes".length));
    if (Number.isFinite(n) && n >= 0) return `0x${"00".repeat(n)}`;
  }
  return "";
}

function placeholderForType(typeName) {
  const t = String(typeName || "");
  if (t === "int") return "0 (or 0x7b)";
  if (t === "bool") return "false";
  if (t === "string") return "hello";
  if (t.endsWith("[]")) return "[] (or 0x...)";
  if (t === "bytes") return "0xdeadbeef";
  if (t === "byte") return "0x00";
  if (t === "pubkey") return "0x.. (32 bytes)";
  if (t === "sig" || t === "datasig") return "0x.. (64 bytes)";
  if (t.startsWith("bytes")) return `0x.. (${t} bytes)`;
  return "0x...";
}

class ApiError extends Error {
  constructor(message, span) {
    super(message);
    this.name = "ApiError";
    this.span = span || null;
  }
}

async function apiGet(path) {
  const res = await fetch(path);
  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = payload && payload.error ? String(payload.error) : `GET ${path} failed (${res.status})`;
    throw new ApiError(msg, payload && payload.span ? payload.span : null);
  }
  return payload;
}

async function apiPost(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = payload && payload.error ? String(payload.error) : `POST ${path} failed (${res.status})`;
    throw new ApiError(msg, payload && payload.span ? payload.span : null);
  }
  return payload;
}

function setDirty(state, isDirty) {
  state.dirty = !!isDirty;
  const dot = $("dirtyDot");
  if (dot) dot.classList.toggle("dirty", state.dirty);
}

function setStatus(left, right) {
  $("statusLeft").textContent = left || "";
  $("statusRight").textContent = right || "";
}

function currentCompileSignature(state) {
  return JSON.stringify({
    source: String($("editor").value || ""),
    function: String((state.run && state.run.function) || ""),
    ctor_args: Array.isArray(state.run && state.run.ctor_args) ? state.run.ctor_args.map((v) => String(v ?? "")) : [],
    args: Array.isArray(state.run && state.run.args) ? state.run.args.map((v) => String(v ?? "")) : [],
    expect_no_selector: !!state.expectNoSelector,
  });
}

function updateRunButton(state) {
  const btnRun = $("btnRun");
  if (!btnRun) return;

  if (state.isCompiling) {
    btnRun.disabled = true;
    btnRun.textContent = "Compiling…";
    btnRun.title = "Compiling trace…";
    return;
  }

  const upToDate = !!state.trace && !!state.lastCompiledSignature && currentCompileSignature(state) === state.lastCompiledSignature;
  btnRun.disabled = upToDate;
  btnRun.textContent = "▶ Compile";
  btnRun.title = upToDate ? "No source/arg changes since last compile" : "Compile Trace (F5)";
}

function setProblems(state, items) {
  state.problems = Array.isArray(items) ? items : [];
  $("problemsMeta").textContent = state.problems.length ? `${state.problems.length}` : "";
  const view = $("problemsView");
  if (!state.problems.length) {
    view.innerHTML = `<div class="problem ok">No problems</div>`;
    return;
  }
  view.innerHTML = state.problems
    .map((p, idx) => {
      const msg = p && p.message ? String(p.message) : String(p);
      const hasSpan = p && p.span && p.span.line;
      const badge = hasSpan ? ` <span class="badge">L${escapeHtml(p.span.line)}</span>` : "";
      return `<div class="problem" data-idx="${idx}">${escapeHtml(msg)}${badge}</div>`;
    })
    .join("");

  view.querySelectorAll(".problem").forEach((el) => {
    el.addEventListener("click", () => {
      const idx = Number(el.dataset.idx || "0");
      const p = state.problems[idx];
      if (p && p.span && p.span.line) {
        focusEditorAtSpan(state, p.span);
      }
    });
  });
}

function focusEditorAtSpan(state, span) {
  const editor = $("editor");
  const line = Number(span.line || 0);
  const col = Number(span.col || 1);
  if (!line) return;

  const lines = String(editor.value || "").split("\n");
  let pos = 0;
  for (let i = 0; i < Math.max(0, line - 1) && i < lines.length; i++) pos += lines[i].length + 1;
  pos += Math.max(0, col - 1);
  pos = clamp(pos, 0, editor.value.length);

  editor.focus();
  editor.setSelectionRange(pos, pos);
  // Selection range often scrolls into view; if not, best-effort with scrollTop.
  const { lineHeight } = editorLineMetrics();
  editor.scrollTop = Math.max(0, (line - 1) * lineHeight - editor.clientHeight / 2);

  state.problemSpan = span;
  renderEditorGutter(state);
}

function getOpcodeSteps(trace) {
  if (!trace) return [];
  if (Array.isArray(trace.opcode_steps) && trace.opcode_steps.length) return trace.opcode_steps;
  if (Array.isArray(trace.steps)) return trace.steps;
  return [];
}

function getSourceSteps(trace) {
  if (!trace) return [];
  if (Array.isArray(trace.source_steps) && trace.source_steps.length) return trace.source_steps;
  if (Array.isArray(trace.steps)) return trace.steps;
  return [];
}

function getActiveSteps(state) {
  if (!state.trace) return [];
  return state.dbg.mode === "opcode" ? getOpcodeSteps(state.trace) : getSourceSteps(state.trace);
}

function frameIdFromStep(step) {
  if (!step) return null;
  if (step.frame_id != null) return Number(step.frame_id);
  if (step.mapping && step.mapping.frame_id != null) return Number(step.mapping.frame_id);
  return null;
}

function frameSpanForFrame(steps, frameId) {
  if (frameId == null) return null;
  const target = Number(frameId);
  let startLine = 0;
  let endLine = 0;
  for (const step of steps || []) {
    const mapping = step && step.mapping;
    if (!mapping || !mapping.span) continue;
    const curFrameId = frameIdFromStep(step);
    if (curFrameId !== target) continue;
    const line = Number(mapping.span.line || 0);
    const end = Number(mapping.span.end_line || line);
    if (!line) continue;
    if (!startLine || line < startLine) startLine = line;
    if (!endLine || end > endLine) endLine = end;
  }
  if (!startLine || !endLine) return null;
  return { startLine, endLine };
}

function updateEditorDecorations(state, snap, fnTintKind) {
  const editor = $("editor");
  if (!editor) return;

  const style = editor.style;
  style.setProperty("--active-line-top", "-1000px");
  style.setProperty("--active-line-height", "0px");
  style.setProperty("--active-line-color", "transparent");
  style.setProperty("--fn-tint-top", "-1000px");
  style.setProperty("--fn-tint-height", "0px");
  style.setProperty("--fn-tint-color", "transparent");
  state.dbg.fnTintSpan = null;
  state.dbg.fnTintKind = null;

  if (!snap) return;

  const { lineHeight, paddingTop } = editorLineMetrics();
  const line = mappingLine(snap.mapping);
  if (line) {
    const activeTop = paddingTop + (Number(line) - 1) * lineHeight;
    style.setProperty("--active-line-top", `${activeTop}px`);
    style.setProperty("--active-line-height", `${lineHeight}px`);
    style.setProperty("--active-line-color", "rgba(255, 217, 102, 0.18)");
  }

  if (!fnTintKind || !state.trace) return;

  const targetFrameId = fnTintKind === "pass" ? 0 : frameIdFromStep(snap);
  const span = frameSpanForFrame(getSourceSteps(state.trace), targetFrameId);
  if (!span) return;

  const tintTop = paddingTop + (span.startLine - 1) * lineHeight;
  const tintHeight = Math.max(lineHeight, (span.endLine - span.startLine + 1) * lineHeight);
  const tintColor = fnTintKind === "pass" ? "rgba(78, 201, 176, 0.10)" : "rgba(241, 76, 76, 0.10)";

  style.setProperty("--fn-tint-top", `${tintTop}px`);
  style.setProperty("--fn-tint-height", `${tintHeight}px`);
  style.setProperty("--fn-tint-color", tintColor);
  state.dbg.fnTintSpan = span;
  state.dbg.fnTintKind = fnTintKind;
}

function getActiveStepIndex(state, steps) {
  const max = Math.max(0, (steps || []).length - 1);
  if (state.dbg.mode === "opcode") return clamp(state.dbg.opcodeStep || 0, 0, max);
  return clamp(state.dbg.sourceStep || 0, 0, max);
}

function setActiveStepIndex(state, idx) {
  if (state.dbg.mode === "opcode") state.dbg.opcodeStep = idx;
  else state.dbg.sourceStep = idx;
}

function activeSnapshot(state) {
  const steps = getActiveSteps(state);
  if (!steps.length) return null;
  const idx = getActiveStepIndex(state, steps);
  setActiveStepIndex(state, idx);
  return steps[idx];
}

function stepDepth(step) {
  if (!step) return 0;
  if (step.call_depth != null) return Number(step.call_depth);
  if (step.mapping && step.mapping.call_depth != null) return Number(step.mapping.call_depth);
  return 0;
}

function sourceIndexFromOpcodeIndex(state, opcodeIndex) {
  const trace = state.trace;
  if (!trace) return 0;
  const opcodeSteps = getOpcodeSteps(trace);
  const sourceSteps = getSourceSteps(trace);
  if (!sourceSteps.length) return 0;
  const opSnap = opcodeSteps[clamp(opcodeIndex, 0, Math.max(0, opcodeSteps.length - 1))];
  const targetPc = opSnap ? Number(opSnap.pc || 0) : 0;

  let best = 0;
  for (let i = 0; i < sourceSteps.length; i++) {
    const stepPc = Number(sourceSteps[i].pc || 0);
    if (stepPc > targetPc) break;
    best = i;
  }
  return best;
}

function syncOpcodeFromSource(state) {
  const trace = state.trace;
  if (!trace) return;
  const opcodeSteps = getOpcodeSteps(trace);
  const sourceSteps = getSourceSteps(trace);
  if (!opcodeSteps.length || !sourceSteps.length) return;
  const srcIdx = clamp(state.dbg.sourceStep || 0, 0, sourceSteps.length - 1);
  const snap = sourceSteps[srcIdx];
  const pc = Number(snap && snap.pc != null ? snap.pc : 0);
  state.dbg.opcodeStep = clamp(pc, 0, opcodeSteps.length - 1);
}

function syncSourceFromOpcode(state) {
  const trace = state.trace;
  if (!trace) return;
  const sourceSteps = getSourceSteps(trace);
  if (!sourceSteps.length) return;
  state.dbg.sourceStep = sourceIndexFromOpcodeIndex(state, state.dbg.opcodeStep || 0);
}

function sourceStepIntoIndex(steps, idx) {
  return clamp(idx + 1, 0, Math.max(0, steps.length - 1));
}

function sourceStepOverIndex(steps, idx) {
  const currentDepth = stepDepth(steps[idx]);
  for (let i = idx + 1; i < steps.length; i++) {
    if (stepDepth(steps[i]) <= currentDepth) return i;
  }
  return Math.max(0, steps.length - 1);
}

function sourceStepOutIndex(steps, idx) {
  const currentDepth = stepDepth(steps[idx]);
  for (let i = idx + 1; i < steps.length; i++) {
    if (stepDepth(steps[i]) < currentDepth) return i;
  }
  return Math.max(0, steps.length - 1);
}

function resetDbgCursor(state) {
  const trace = state.trace;
  if (!trace) return;
  const sourceSteps = getSourceSteps(trace);
  const opcodeSteps = getOpcodeSteps(trace);
  state.dbg.sourceStep = 0;
  state.dbg.opcodeStep = 0;
  state.dbg.mode = sourceSteps.length ? "source" : "opcode";
  if (sourceSteps.length && opcodeSteps.length) syncOpcodeFromSource(state);
}

function renderEditorGutter(state) {
  const editor = $("editor");
  const gutter = $("editorGutter");
  const lines = String(editor.value || "").split("\n").length;
  const errLine = state.problemSpan && state.problemSpan.line ? Number(state.problemSpan.line) : 0;
  const snap = activeSnapshot(state);
  const activeLine = snap ? mappingLine(snap.mapping) : 0;
  const fnTintSpan = state.dbg && state.dbg.fnTintSpan ? state.dbg.fnTintSpan : null;
  const fnTintKind = state.dbg && state.dbg.fnTintKind ? String(state.dbg.fnTintKind) : null;
  let html = "";
  for (let i = 1; i <= lines; i++) {
    const cls = ["gline"];
    if (errLine === i) cls.push("error");
    if (fnTintSpan && i >= fnTintSpan.startLine && i <= fnTintSpan.endLine) {
      cls.push(fnTintKind === "pass" ? "fn-pass" : "fn-fail");
    }
    if (activeLine === i) cls.push("active");
    if (state.dbg && state.dbg.breakpoints && state.dbg.breakpoints.has(i)) cls.push("bp");
    html += `<div class="${cls.join(" ")}" data-line="${i}"><span class="bp-dot"></span><span class="ln">${i}</span></div>`;
  }
  gutter.innerHTML = html;
  gutter.scrollTop = editor.scrollTop;
}

function normalizeArgs(params, current) {
  const out = Array.isArray(current) ? [...current] : [];
  while (out.length < params.length) out.push("");
  if (out.length > params.length) out.length = params.length;

  for (let i = 0; i < params.length; i++) {
    const t = String(params[i].type_name || "");
    const v = out[i];
    if (v == null || String(v).trim() === "") out[i] = defaultArgValue(t);
  }

  return out;
}

function renderArgsList(targetId, params, values, onChange, state) {
  const view = $(targetId);
  if (!params || !params.length) {
    view.innerHTML = `<div class="muted">none</div>`;
    return;
  }

  const next = normalizeArgs(params, values);
  const rows = [];
  for (let i = 0; i < params.length; i++) {
    const p = params[i];
    const type = String(p.type_name || "");
    const name = String(p.name || `arg${i}`);
    const placeholder = placeholderForType(type);
    const hasKeyBtn = isKeyType(type);
    const inputHtml = hasKeyBtn
      ? `<div class="arg-input-wrap">
          <input data-idx="${i}" data-type="${escapeHtml(type)}" value="${escapeHtml(next[i] || "")}" placeholder="${escapeHtml(placeholder)}" />
          <button class="arg-gen-btn" data-idx="${i}" data-type="${escapeHtml(type)}" title="Pick from wallet or generate">🔑</button>
        </div>`
      : `<input data-idx="${i}" value="${escapeHtml(next[i] || "")}" placeholder="${escapeHtml(placeholder)}" />`;
    rows.push(
      `<div class="arg-row">
        <div class="arg-meta">
          <span><code>${escapeHtml(type)}</code> ${escapeHtml(name)}</span>
          <span class="badge">#${i}</span>
        </div>
        ${inputHtml}
      </div>`
    );
  }
  view.innerHTML = rows.join("");
  view.querySelectorAll("input[data-idx]").forEach((inp) => {
    inp.addEventListener("input", () => {
      const idx = Number(inp.dataset.idx || "0");
      next[idx] = String(inp.value || "");
      onChange(next);
    });
  });

  // Wire up inline key gen/pick buttons
  view.querySelectorAll(".arg-gen-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const idx = Number(btn.dataset.idx || "0");
      const type = btn.dataset.type || "pubkey";
      showArgKeyDropdown(btn, idx, type, next, onChange, state);
    });
  });
}

function closeAllDropdowns() {
  document.querySelectorAll(".arg-key-dropdown").forEach((d) => d.remove());
}

function showArgKeyDropdown(anchorBtn, argIdx, typeName, argsArr, onChange, state) {
  closeAllDropdowns();
  const keys = state.keys || [];
  const fieldLabel = typeName === "pubkey" ? "pubkey" : (typeName === "bytes20" || typeName === "bytes32") ? "pkh" : "sig";

  const dd = document.createElement("div");
  dd.className = "arg-key-dropdown";

  let html = "";
  // Generate new option
  html += `<div class="arg-key-dropdown-gen" data-action="gen">🔑 Generate new & fill</div>`;

  if (keys.length) {
    html += `<div class="arg-key-dropdown-header">Use from wallet (${fieldLabel})</div>`;
    for (let i = 0; i < keys.length; i++) {
      const val = keyValueForType(keys[i], typeName);
      const short = String(val).slice(0, 10) + "…";
      html += `<div class="arg-key-dropdown-item" data-kidx="${i}">
        <span class="dk-name">${escapeHtml(keys[i].name)}</span>
        <span class="dk-val">${escapeHtml(short)}</span>
      </div>`;
    }
  }
  dd.innerHTML = html;

  // Position relative to the arg-row
  const argRow = anchorBtn.closest(".arg-row");
  argRow.appendChild(dd);

  // Generate new and fill
  dd.querySelector("[data-action=gen]").addEventListener("click", async () => {
    const kp = await generateKeypair(keys);
    state.keys.push(kp);
    saveKeys(state.keys);
    renderKeyWallet(state);
    const val = keyValueForType(kp, typeName);
    argsArr[argIdx] = val;
    const inp = argRow.querySelector(`input[data-idx="${argIdx}"]`);
    if (inp) inp.value = val;
    onChange(argsArr);
    showToast(`${kp.name} → ${typeName}`);
    closeAllDropdowns();
  });

  // Pick from existing
  dd.querySelectorAll(".arg-key-dropdown-item").forEach((item) => {
    item.addEventListener("click", () => {
      const kidx = Number(item.dataset.kidx);
      const val = keyValueForType(keys[kidx], typeName);
      argsArr[argIdx] = val;
      const inp = argRow.querySelector(`input[data-idx="${argIdx}"]`);
      if (inp) inp.value = val;
      onChange(argsArr);
      showToast(`${keys[kidx].name} → ${typeName}`);
      closeAllDropdowns();
    });
  });

  // Close on outside click
  const closer = (e) => {
    if (!dd.contains(e.target) && e.target !== anchorBtn) {
      closeAllDropdowns();
      document.removeEventListener("click", closer);
    }
  };
  setTimeout(() => document.addEventListener("click", closer), 0);
}

function renderRunForm(state) {
  const outline = state.outline;
  const fnSelect = document.getElementById("fnSelect");
  const el = (id) => document.getElementById(id);

  if (!outline) {
    if (fnSelect) {
      fnSelect.innerHTML = `<option value="">(fix syntax errors)</option>`;
      fnSelect.disabled = true;
    }
    if (el("selectorMeta")) el("selectorMeta").textContent = "selector: —";
    if (el("sigscriptMeta")) el("sigscriptMeta").textContent = "sigscript: —";
    if (el("ctorArgsView")) el("ctorArgsView").innerHTML = `<div class="muted">—</div>`;
    if (el("fnArgsView")) el("fnArgsView").innerHTML = `<div class="muted">—</div>`;
    if (el("sigscriptHex")) el("sigscriptHex").textContent = "—";
    if (el("sigscriptHint")) el("sigscriptHint").textContent = "";
    return;
  }

  const fns = Array.isArray(outline.functions) ? outline.functions : [];

  // If fnSelect exists in the DOM, populate it
  if (fnSelect) {
    fnSelect.disabled = fns.length === 0;
    fnSelect.innerHTML = fns
      .map((f) => {
        const sig = `${f.name}(${(f.inputs || []).map((p) => p.type_name).join(", ")})`;
        return `<option value="${escapeHtml(f.name)}">${escapeHtml(sig)}</option>`;
      })
      .join("");
  }

  // Pick a valid function if current isn't present
  const names = new Set(fns.map((f) => f.name));
  if (!state.run.function || !names.has(state.run.function)) state.run.function = fns.length ? fns[0].name : "";
  if (fnSelect) fnSelect.value = state.run.function || "";

  const selected = fns.find((f) => f.name === state.run.function) || null;
  const selectorIndex = selected && selected.selector_index != null ? Number(selected.selector_index) : null;
  if (el("selectorMeta")) el("selectorMeta").textContent = outline.without_selector ? "selector: none (single entrypoint)" : selectorIndex == null ? "selector: —" : `selector: #${selectorIndex}`;

  // Normalize arg arrays (defaults!)
  const ctorParams = Array.isArray(outline.constructor_params) ? outline.constructor_params : [];
  state.run.ctor_args = normalizeArgs(ctorParams, state.run.ctor_args);
  const fnParams = selected && Array.isArray(selected.inputs) ? selected.inputs : [];
  state.run.args = normalizeArgs(fnParams, state.run.args);

  renderArgsList("ctorArgsView", ctorParams, state.run.ctor_args, (next) => {
    state.run.ctor_args = next;
    setDirty(state, true);
    updateRunButton(state);
    triggerSigscript(state);
  }, state);
  renderArgsList("fnArgsView", fnParams, state.run.args, (next) => {
    state.run.args = next;
    setDirty(state, true);
    updateRunButton(state);
    triggerSigscript(state);
  }, state);

  if (el("runMeta")) el("runMeta").textContent = `${fns.length} entrypoints`;
  updateRunButton(state);
}

async function refreshOutline(state, { reason } = {}) {
  const source = String($("editor").value || "");
  const reqId = ++state.outlineReqId;
  try {
    const outline = await apiPost("/api/outline", { source });
    if (reqId !== state.outlineReqId) return;
    state.outline = outline;
    state.problemSpan = null;
    setProblems(state, []);
    renderEditorGutter(state);
    renderRunForm(state);
    renderContractMeta(state);
    triggerSigscript(state);
  } catch (err) {
    if (reqId !== state.outlineReqId) return;
    state.outline = null;
    const span = err instanceof ApiError ? err.span : null;
    state.problemSpan = span;
    setProblems(state, [{ message: String(err.message || err), span }]);
    renderEditorGutter(state);
    renderRunForm(state);
    renderContractMeta(state);
  }
}

function renderContractMeta(state) {
  const outline = state.outline;
  const t = state.trace;
  if (t && t.meta) {
    const m = t.meta;
    const selector = m.selector_index != null ? `selector #${m.selector_index}` : "selector none";
    const sig = m.sigscript_len != null ? `${m.sigscript_len}b sigscript` : "";
    const srcSteps = m.source_step_count != null ? `${m.source_step_count} src-steps` : null;
    $("contractMeta").textContent = `${m.contract_name} :: ${m.function_name} | ${selector} | ${m.script_len}b script | ${m.opcode_count} ops${srcSteps ? " | " + srcSteps : ""} ${sig ? "| " + sig : ""}`;
    return;
  }
  if (outline) {
    $("contractMeta").textContent = `${outline.contract_name}${state.run.function ? " :: " + state.run.function : ""}`;
    return;
  }
  $("contractMeta").textContent = "…";
}

const triggerSigscript = debounce(async (state) => {
  await refreshSigscript(state);
}, 220);

async function refreshSigscript(state) {
  const outline = state.outline;
  if (!outline || !state.run.function) return;

  const source = String($("editor").value || "");
  try {
    const payload = await apiPost("/api/sigscript", {
      source,
      function: state.run.function,
      ctor_args: Array.isArray(state.run.ctor_args) ? state.run.ctor_args : [],
      args: Array.isArray(state.run.args) ? state.run.args : [],
      expect_no_selector: !!state.expectNoSelector,
    });
    const el = (id) => document.getElementById(id);
    if (el("sigscriptHex")) el("sigscriptHex").textContent = payload.sigscript_hex ? `0x${payload.sigscript_hex}` : "—";
    if (el("sigscriptHint")) el("sigscriptHint").textContent = payload.sigscript_hex ? bytesHint(payload.sigscript_hex) : "";
    if (el("sigscriptMeta")) el("sigscriptMeta").textContent = payload.sigscript_len != null ? `sigscript: ${payload.sigscript_len} bytes` : "sigscript: —";
    if (payload.selector_index != null && !payload.without_selector) {
      if (el("selectorMeta")) el("selectorMeta").textContent = `selector: #${payload.selector_index}`;
    }
  } catch (err) {
    const el = (id) => document.getElementById(id);
    if (el("sigscriptHex")) el("sigscriptHex").textContent = "—";
    if (el("sigscriptHint")) el("sigscriptHint").textContent = String(err.message || err);
    if (el("sigscriptMeta")) el("sigscriptMeta").textContent = "sigscript: —";
  }
}

async function runTrace(state, { openDebug } = {}) {
  const outline = state.outline;
  if (!outline) {
    setStatus("fix syntax errors before running", "");
    return;
  }

  const source = String($("editor").value || "");
  state.isCompiling = true;
  updateRunButton(state);
  setStatus("compiling trace…", "");
  try {
    const trace = await apiPost("/api/trace", {
      source,
      function: state.run.function,
      ctor_args: Array.isArray(state.run.ctor_args) ? state.run.ctor_args : [],
      args: Array.isArray(state.run.args) ? state.run.args : [],
      expect_no_selector: !!state.expectNoSelector,
    });
    state.trace = trace;
    // Reflect what the server actually ran (defaults may be filled server-side).
    state.run.function = trace && trace.meta ? String(trace.meta.function_name || state.run.function) : state.run.function;
    state.run.ctor_args = trace && trace.meta && Array.isArray(trace.meta.ctor_args) ? trace.meta.ctor_args : state.run.ctor_args;
    state.run.args = trace && trace.meta && Array.isArray(trace.meta.args) ? trace.meta.args : state.run.args;
    state.problemSpan = null;
    setProblems(state, []);
    renderEditorGutter(state);
    renderRunForm(state);
    resetDbgCursor(state);
    // Keep breakpoints across runs; they are line-based and useful while iterating.
    state.dbg.filter = "";
    $("dbgOpFilter").value = "";
    renderContractMeta(state);
    // Also update the sidebar sigscript box from the trace metadata (if present).
    if (trace && trace.meta && trace.meta.sigscript_hex) {
      const el = (id) => document.getElementById(id);
      if (el("sigscriptHex")) el("sigscriptHex").textContent = `0x${trace.meta.sigscript_hex}`;
      if (el("sigscriptHint")) el("sigscriptHint").textContent = bytesHint(trace.meta.sigscript_hex);
      if (el("sigscriptMeta")) el("sigscriptMeta").textContent = `sigscript: ${trace.meta.sigscript_len} bytes`;
    }
    state.lastCompiledSignature = currentCompileSignature(state);
    setDirty(state, false);
    renderDbg(state);
    setStatus("trace ready", "");
    if (openDebug !== false) scrollEditorToActive(state);
  } catch (err) {
    const span = err instanceof ApiError ? err.span : null;
    state.problemSpan = span;
    setProblems(state, [{ message: String(err.message || err), span }]);
    renderEditorGutter(state);
    setStatus(`ERROR: ${String(err.message || err)}`, "");
  } finally {
    state.isCompiling = false;
    updateRunButton(state);
  }
}

function scrollEditorToLine(state, line, { behavior } = {}) {
  const editor = $("editor");
  const ln = Number(line || 0);
  if (!ln) return;
  // Selection range often scrolls into view; if not, best-effort with scrollTop.
  const { lineHeight } = editorLineMetrics();
  const target = Math.max(0, (ln - 1) * lineHeight - editor.clientHeight / 2);
  editor.scrollTo({ top: target, behavior: behavior || "smooth" });
  $("editorGutter").scrollTop = editor.scrollTop;
}

function scrollEditorToActive(state, { behavior } = {}) {
  const snap = activeSnapshot(state);
  if (!snap) return;
  const line = mappingLine(snap.mapping);
  if (!line) return;
  scrollEditorToLine(state, line, { behavior });
}

function stepIntoSource(state) {
  const trace = state.trace;
  if (!trace) return;
  const sourceSteps = getSourceSteps(trace);
  if (!sourceSteps.length) return;
  if (state.dbg.mode === "opcode") syncSourceFromOpcode(state);
  state.dbg.mode = "source";
  const idx = clamp(state.dbg.sourceStep || 0, 0, sourceSteps.length - 1);
  state.dbg.sourceStep = sourceStepIntoIndex(sourceSteps, idx);
  syncOpcodeFromSource(state);
}

function stepOverSource(state) {
  const trace = state.trace;
  if (!trace) return;
  const sourceSteps = getSourceSteps(trace);
  if (!sourceSteps.length) return;
  if (state.dbg.mode === "opcode") syncSourceFromOpcode(state);
  state.dbg.mode = "source";
  const idx = clamp(state.dbg.sourceStep || 0, 0, sourceSteps.length - 1);
  state.dbg.sourceStep = sourceStepOverIndex(sourceSteps, idx);
  syncOpcodeFromSource(state);
}

function stepOutSource(state) {
  const trace = state.trace;
  if (!trace) return;
  const sourceSteps = getSourceSteps(trace);
  if (!sourceSteps.length) return;
  if (state.dbg.mode === "opcode") syncSourceFromOpcode(state);
  state.dbg.mode = "source";
  const idx = clamp(state.dbg.sourceStep || 0, 0, sourceSteps.length - 1);
  state.dbg.sourceStep = sourceStepOutIndex(sourceSteps, idx);
  syncOpcodeFromSource(state);
}

function stepOpcode(state, delta) {
  const trace = state.trace;
  if (!trace) return;
  const opcodeSteps = getOpcodeSteps(trace);
  if (!opcodeSteps.length) return;
  if (state.dbg.mode !== "opcode") syncOpcodeFromSource(state);
  state.dbg.mode = "opcode";
  const idx = clamp((state.dbg.opcodeStep || 0) + delta, 0, opcodeSteps.length - 1);
  state.dbg.opcodeStep = idx;
  syncSourceFromOpcode(state);
}

function continueToBreakpoint(state) {
  const trace = state.trace;
  if (!trace) return 0;
  const sourceSteps = getSourceSteps(trace);
  if (!sourceSteps.length) return 0;

  if (state.dbg.mode === "opcode") syncSourceFromOpcode(state);
  const start = clamp(state.dbg.sourceStep || 0, 0, sourceSteps.length - 1);
  const last = sourceSteps.length - 1;
  if (!state.dbg.breakpoints.size) return last;
  for (let k = start + 1; k < sourceSteps.length; k++) {
    const s = sourceSteps[k];
    if (!s.is_executing) continue;
    const line = mappingLine(s.mapping);
    if (line && state.dbg.breakpoints.has(line)) return k;
  }
  return last;
}

function continueExecution(state) {
  if (!state.trace) return;
  const sourceSteps = getSourceSteps(state.trace);
  if (sourceSteps.length) {
    state.dbg.mode = "source";
    state.dbg.sourceStep = continueToBreakpoint(state);
    syncOpcodeFromSource(state);
    return;
  }
  const opcodeSteps = getOpcodeSteps(state.trace);
  state.dbg.mode = "opcode";
  state.dbg.opcodeStep = Math.max(0, opcodeSteps.length - 1);
}

function setDbgEnabled(enabled) {
  const ids = [
    "btnDbgStepOver",
    "btnDbgStepInto",
    "btnDbgStepOut",
    "btnDbgOpcodePrev",
    "btnDbgOpcodeNext",
    "btnDbgContinue",
    "dbgOpFilter",
    "btnDbgRestart",
    "btnDbgStop",
  ];
  for (const id of ids) {
    const el = document.getElementById(id);
    if (!el) continue;
    el.disabled = !enabled;
  }
}

function setDbgTab(state, tab) {
  const t = String(tab || "vars");
  state.dbg.tab = t;

  const tabs = [
    ["vars", "dbgTabVars", "dbgPanelVars"],
    ["stack", "dbgTabStack", "dbgPanelStack"],
    ["ops", "dbgTabOps", "dbgPanelOps"],
    ["bps", "dbgTabBps", "dbgPanelBps"],
  ];
  for (const [key, btnId, panelId] of tabs) {
    const btn = document.getElementById(btnId);
    const panel = document.getElementById(panelId);
    if (btn) btn.classList.toggle("active", key === t);
    if (panel) panel.hidden = key !== t;
  }
}

function renderDbgBps(state) {
  const view = $("dbgBpsView");
  const bps = state.dbg && state.dbg.breakpoints ? [...state.dbg.breakpoints] : [];
  bps.sort((a, b) => a - b);
  if (!bps.length) {
    view.innerHTML = `<div class="problem ok">No breakpoints. Click the gutter to add.</div>`;
    return;
  }
  view.innerHTML = bps
    .map((ln) => `<div class="problem" data-line="${ln}">Line ${ln} <span class="badge">L${ln}</span></div>`)
    .join("");

  view.querySelectorAll(".problem").forEach((el) => {
    el.addEventListener("click", () => {
      const line = Number(el.dataset.line || "0");
      if (!line) return;
      state.dbg.breakpoints.delete(line);
      renderEditorGutter(state);
      renderDbgBps(state);
    });
  });
}

function renderDbg(state) {
  const trace = state.trace;
  if (!trace) {
    setDbgEnabled(false);
    updateEditorDecorations(state, null, null);
    $("execIcon").textContent = "○";
    $("execLabel").textContent = "Ready";
    $("dbgExecPill").classList.remove("success", "error", "running");
    $("dbgVarsMeta").textContent = "";
    $("dbgVarsView").innerHTML = `<div class="muted" style="padding:10px 12px;">Press Run to build a trace.</div>`;
    $("dbgDstackView").innerHTML = `<div class="muted">—</div>`;
    $("dbgAstackView").innerHTML = `<div class="muted">—</div>`;
    $("dbgOpsView").innerHTML = `<div class="muted" style="padding:10px 12px;">—</div>`;
    renderDbgBps(state);
    return;
  }
  setDbgEnabled(true);

  const sourceSteps = getSourceSteps(trace);
  const opcodeSteps = getOpcodeSteps(trace);
  if (state.dbg.mode === "source" && !sourceSteps.length) state.dbg.mode = "opcode";
  if (state.dbg.mode === "opcode" && !opcodeSteps.length) state.dbg.mode = sourceSteps.length ? "source" : "opcode";

  const steps = getActiveSteps(state);
  if (!steps.length) {
    updateEditorDecorations(state, null, null);
    $("dbgVarsView").innerHTML = `<div class="muted" style="padding:10px 12px;">No trace steps.</div>`;
    $("dbgDstackView").innerHTML = `<div class="muted">—</div>`;
    $("dbgAstackView").innerHTML = `<div class="muted">—</div>`;
    $("dbgOpsView").innerHTML = `<div class="muted" style="padding:10px 12px;">—</div>`;
    renderDbgBps(state);
    return;
  }

  const step = getActiveStepIndex(state, steps);
  setActiveStepIndex(state, step);
  const snap = steps[step];
  const line = mappingLine(snap.mapping);
  const label = mappingLabel(snap.mapping);
  const err = snap.error ? String(snap.error) : null;
  const isLast = step === steps.length - 1;
  const modeLabel = state.dbg.mode === "source" ? "source" : "opcode";
  const depth = stepDepth(snap);
  const frame = snap.frame_id != null ? snap.frame_id : snap.mapping && snap.mapping.frame_id != null ? snap.mapping.frame_id : null;
  const sequence =
    snap.sequence != null ? snap.sequence : snap.mapping && snap.mapping.sequence != null ? snap.mapping.sequence : null;
  const callStack = Array.isArray(snap.call_stack) ? snap.call_stack : [];

  const pill = $("dbgExecPill");
  pill.classList.remove("success", "error", "running");

  const icon = $("execIcon");
  const execLabelEl = $("execLabel");

  if (err) {
    icon.textContent = "\u2717";
    execLabelEl.textContent = "FAILED";
    pill.classList.add("error");
  } else if (!snap.is_executing || isLast) {
    icon.textContent = "✓";
    execLabelEl.textContent = "PASSED";
    pill.classList.add("success");
  } else {
    icon.textContent = "▶";
    execLabelEl.textContent = `${modeLabel} ${step + 1}/${steps.length}`;
    pill.classList.add("running");
  }

  // Update step indicator in panel title
  const stepIndicator = $("stepIndicator");
  if (stepIndicator) {
    const modeTitle = state.dbg.mode === "source" ? "Source" : "Opcode";
    stepIndicator.textContent = `${modeTitle} ${step + 1} of ${steps.length}`;
  }

  const statusBits = [];
  if (sequence != null) statusBits.push(`seq=${sequence}`);
  if (frame != null) statusBits.push(`frame=${frame}`);
  statusBits.push(`depth=${depth}`);

  setStatus(
    `${modeLabel} step ${step}/${steps.length - 1} | pc=${snap.pc} | off=${snap.byte_offset} | ${statusBits.join(" | ")} | ${snap.last_opcode ? "last=" + snap.last_opcode : "start"
    }${err ? " | ERROR: " + err : ""}${!snap.is_executing && !err ? " | SCRIPT PASSED" : ""}`,
    `${line ? "line " + line : "no span"}${label ? " | " + label : ""}${callStack.length ? " | call: " + callStack.join(" > ") : ""}`
  );

  const fnTintKind = err ? "fail" : (!snap.is_executing || isLast) ? "pass" : null;
  updateEditorDecorations(state, snap, fnTintKind);
  renderEditorGutter(state);

  renderDbgOps(state);
  renderStack("dbgDstackView", snap.stacks.dstack);
  renderStack("dbgAstackView", snap.stacks.astack);
  renderVars(
    "dbgVarsView",
    "dbgVarsMeta",
    snap.vars || [],
    err,
    `${modeLabel}${callStack.length ? " | call: " + callStack.join(" > ") : ""}`
  );
  renderDbgBps(state);
  scrollOpsToStep();
  scrollEditorToActive(state, { behavior: "auto" });
}

function scrollOpsToStep() {
  const current = document.querySelector(`.op-row.current`);
  if (current) current.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

function renderDbgOps(state) {
  const trace = state.trace;
  const opcodeSteps = getOpcodeSteps(trace);
  if (!opcodeSteps.length) {
    $("dbgOpsView").innerHTML = `<div class="muted">No ops</div>`;
    return;
  }
  const activeOpcodeStep =
    state.dbg.mode === "opcode"
      ? clamp(state.dbg.opcodeStep || 0, 0, opcodeSteps.length - 1)
      : clamp(
        Number((getSourceSteps(trace)[clamp(state.dbg.sourceStep || 0, 0, Math.max(0, getSourceSteps(trace).length - 1))] || {}).pc || 0),
        0,
        opcodeSteps.length - 1
      );
  const filter = String(state.dbg.filter || "").trim().toLowerCase();
  const view = $("dbgOpsView");

  const rows = [];
  for (const op of trace.opcodes) {
    const line = mappingLine(op.mapping);
    const label = mappingLabel(op.mapping);
    const display = op.display || "";
    const hay = `${op.index} ${op.byte_offset} ${display} ${label || ""} ${line || ""}`.toLowerCase();
    if (filter && !hay.includes(filter)) continue;

    const classes = ["op-row"];
    if (op.index < activeOpcodeStep) classes.push("executed");
    if (op.index === activeOpcodeStep || (activeOpcodeStep >= trace.opcodes.length && op.index === trace.opcodes.length - 1)) {
      classes.push("current");
    }
    if (op.index === activeOpcodeStep + 1) classes.push("next");

    const badges = [];
    if (line) badges.push(`<span class="badge">${escapeHtml("L" + line)}</span>`);
    if (label) {
      const cls =
        label === "stmt" ? "badge statement" : label === "virtual" ? "badge statement" : label.startsWith("syn:") ? "badge synthetic" : "badge";
      badges.push(`<span class="${cls}">${escapeHtml(label)}</span>`);
    }

    rows.push(
      `<div class="${classes.join(" ")}" data-opindex="${op.index}">
        <div class="op-meta">#${op.index}<br/>@${op.byte_offset}</div>
        <div class="op-body">
          <div class="op-display">${escapeHtml(display)}</div>
          <div class="op-badges">${badges.join("")}</div>
        </div>
      </div>`
    );
  }

  view.innerHTML = rows.join("") || `<div class="muted">No ops</div>`;
  view.querySelectorAll(".op-row").forEach((row) => {
    row.addEventListener("click", () => {
      const idx = Number(row.dataset.opindex || "0");
      state.dbg.mode = "opcode";
      state.dbg.opcodeStep = clamp(idx, 0, opcodeSteps.length - 1);
      syncSourceFromOpcode(state);
      renderDbg(state);
      scrollEditorToActive(state);
    });
  });
}

function renderStack(targetId, items) {
  const view = $(targetId);
  const arr = Array.isArray(items) ? items : [];
  const rows = [];
  const reversed = [...arr].reverse();
  for (let i = 0; i < reversed.length; i++) {
    const hex = reversed[i];
    rows.push(
      `<div class="stack-item" title="Click to copy">
        <div class="stack-idx">${i}</div>
        <div class="stack-val">
          <div>0x${escapeHtml(hex)}</div>
          <div class="stack-hint">${escapeHtml(bytesHint(hex))}</div>
        </div>
      </div>`
    );
  }
  view.innerHTML = rows.length ? rows.join("") : `<div class="muted">empty</div>`;
  view.querySelectorAll(".stack-item").forEach((el, i) => {
    el.addEventListener("click", async () => {
      const hex = reversed[i] || "";
      await navigator.clipboard.writeText(`0x${hex}`);
    });
  });
}

function renderVars(viewId, metaId, vars, error, metaSuffix) {
  const view = $(viewId);
  let html = "";
  const scopePriority = (origin) => {
    if (origin === "const") return 0;
    if (origin === "arg") return 1;
    return 2;
  };
  const scopeLabel = (origin) => {
    if (origin === "const") return "const";
    if (origin === "arg") return "arg";
    return "var";
  };
  const ordered = [...vars].sort((a, b) => {
    const byScope = scopePriority(String(a.origin || "local")) - scopePriority(String(b.origin || "local"));
    if (byScope !== 0) return byScope;
    return String(a.name || "").localeCompare(String(b.name || ""));
  });
  const rows = [];
  for (const v of ordered) {
    const origin = String(v.origin || "local");
    const scope = scopeLabel(origin);
    const scopeClass = scope === "const" ? "scope-const" : scope === "arg" ? "scope-arg" : "scope-var";
    rows.push(
      `<tr>
        <td>${escapeHtml(v.name)}</td>
        <td class="scope-cell"><span class="origin-pill ${scopeClass}">${escapeHtml(scope)}</span></td>
        <td>${escapeHtml(v.type_name)}</td>
        <td>${escapeHtml(v.value)}</td>
      </tr>`
    );
  }
  html += `<table class="vars-table">
      <thead><tr><th>Name</th><th>Scope</th><th>Type</th><th>Value</th></tr></thead>
      <tbody>${rows.join("")}</tbody>
    </table>`;
  view.innerHTML = html;
  $(metaId).textContent = `${ordered.length} vars${metaSuffix ? " | " + metaSuffix : ""}`;
}

function toggleHelp(state, on) {
  const visible = on != null ? !!on : $("helpOverlay").hidden;
  $("helpOverlay").hidden = !visible;
}

function setupLayoutSplitter() {
  const splitter = document.getElementById("layoutSplitter");
  const root = document.documentElement;
  if (!splitter) return;

  const STORAGE_KEY = "sil_debug_inspector_width";
  const MIN_WIDTH = 280;
  const MAX_WIDTH = 760;

  const apply = (widthPx) => {
    root.style.setProperty("--inspector-width", `${widthPx}px`);
  };

  const restore = () => {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const n = Number(raw);
    if (Number.isFinite(n) && n > 0) apply(clampInt(n, MIN_WIDTH, MAX_WIDTH));
  };

  restore();

  splitter.addEventListener("pointerdown", (e) => {
    if (window.matchMedia("(max-width: 1024px)").matches) return;

    e.preventDefault();
    splitter.classList.add("dragging");

    const current =
      Number.parseInt(getComputedStyle(root).getPropertyValue("--inspector-width"), 10) ||
      Math.round(document.querySelector(".inspector")?.getBoundingClientRect().width || 400);
    const startX = e.clientX;
    const startWidth = clampInt(current, MIN_WIDTH, MAX_WIDTH);

    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    const onMove = (ev) => {
      const dx = ev.clientX - startX;
      const next = clampInt(startWidth - dx, MIN_WIDTH, MAX_WIDTH);
      apply(next);
    };

    const onUp = () => {
      splitter.classList.remove("dragging");
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);

      const finalWidth =
        Number.parseInt(getComputedStyle(root).getPropertyValue("--inspector-width"), 10) || startWidth;
      localStorage.setItem(STORAGE_KEY, String(clampInt(finalWidth, MIN_WIDTH, MAX_WIDTH)));
    };

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  });
}

async function main() {
  const init = await apiGet("/api/init");

  const state = {
    expectNoSelector: !!init.expect_no_selector,
    dirty: false,
    lastCompiledSignature: null,
    isCompiling: false,
    outline: null,
    outlineReqId: 0,
    problems: [],
    problemSpan: null,
    run: {
      function: init.run && init.run.function ? String(init.run.function) : "",
      ctor_args: init.run && Array.isArray(init.run.ctor_args) ? init.run.ctor_args : [],
      args: init.run && Array.isArray(init.run.args) ? init.run.args : [],
    },
    trace: null,
    dbg: {
      mode: "source",
      sourceStep: 0,
      opcodeStep: 0,
      breakpoints: new Set(),
      filter: "",
      tab: "vars",
      fnTintSpan: null,
      fnTintKind: null,
    },
    keys: loadKeys(),
  };

  $("editor").value = String(init.source || "");
  renderEditorGutter(state);
  setDirty(state, false);
  updateRunButton(state);
  setupLayoutSplitter();
  setDbgTab(state, "vars");
  renderDbg(state);
  renderKeyWallet(state);
  setStatus("ready", "");

  // Key Wallet events
  $("btnGenKey").addEventListener("click", async () => {
    const kp = await generateKeypair(state.keys);
    state.keys.push(kp);
    saveKeys(state.keys);
    renderKeyWallet(state);
    showToast(`Generated ${kp.name}`);
    // Flash the new entry
    const entries = $("keysListView").querySelectorAll(".key-entry");
    const last = entries[entries.length - 1];
    if (last) last.classList.add("just-added");
  });

  $("btnClearKeys").addEventListener("click", () => {
    if (!state.keys.length) return;
    if (!window.confirm(`Delete all ${state.keys.length} key(s)?`)) return;
    state.keys = [];
    saveKeys(state.keys);
    renderKeyWallet(state);
  });

  // Run form events (if present in DOM)
  if (document.getElementById("fnSelect")) {
    $("fnSelect").addEventListener("change", (e) => {
      state.run.function = String(e.target.value || "").trim();
      if (state.outline) {
        const fns = Array.isArray(state.outline.functions) ? state.outline.functions : [];
        const f = fns.find((x) => x.name === state.run.function);
        const params = f && Array.isArray(f.inputs) ? f.inputs : [];
        state.run.args = normalizeArgs(params, []);
        setDirty(state, true);
        updateRunButton(state);
        renderRunForm(state);
        triggerSigscript(state);
      }
    });
  }

  if (document.getElementById("btnCopySigscript")) {
    $("btnCopySigscript").addEventListener("click", async () => {
      const raw = String($("sigscriptHex").textContent || "").trim();
      if (!raw || raw === "—") return;
      await navigator.clipboard.writeText(raw);
    });
  }

  // Editor events
  $("editor").addEventListener("input", () => {
    setDirty(state, true);
    updateRunButton(state);
    state.problemSpan = null;
    renderEditorGutter(state);
    refreshOutlineDebounced();
  });
  $("editor").addEventListener("scroll", () => {
    $("editorGutter").scrollTop = $("editor").scrollTop;
  });

  const refreshOutlineDebounced = debounce(async () => {
    await refreshOutline(state, { reason: "typing" });
  }, 250);

  // Top actions
  $("btnRun").addEventListener("click", async () => {
    await runTrace(state);
  });
  $("btnHelp").addEventListener("click", () => toggleHelp(state, true));
  $("btnCloseHelp").addEventListener("click", () => toggleHelp(state, false));
  $("helpOverlay").addEventListener("click", (e) => {
    if (e.target && e.target.id === "helpOverlay") toggleHelp(state, false);
  });

  // Debug tabs
  $("dbgTabVars").addEventListener("click", () => setDbgTab(state, "vars"));
  $("dbgTabStack").addEventListener("click", () => setDbgTab(state, "stack"));
  $("dbgTabOps").addEventListener("click", () => setDbgTab(state, "ops"));
  $("dbgTabBps").addEventListener("click", () => setDbgTab(state, "bps"));
  $("btnDbgClearBps").addEventListener("click", () => {
    state.dbg.breakpoints.clear();
    renderEditorGutter(state);
    renderDbgBps(state);
  });

  // Breakpoints: click editor gutter (works before/after trace)
  $("editorGutter").addEventListener("click", (e) => {
    const row = e.target.closest(".gline");
    if (!row) return;
    const line = Number(row.dataset.line || "0");
    if (!line) return;
    if (state.dbg.breakpoints.has(line)) state.dbg.breakpoints.delete(line);
    else state.dbg.breakpoints.add(line);
    renderEditorGutter(state);
    renderDbgBps(state);
  });

  $("dbgOpFilter").addEventListener("input", (e) => {
    state.dbg.filter = String(e.target.value || "");
    renderDbg(state);
  });
  $("btnDbgStepOver").addEventListener("click", () => {
    if (!state.trace) return;
    stepOverSource(state);
    renderDbg(state);
  });
  $("btnDbgStepInto").addEventListener("click", () => {
    if (!state.trace) return;
    stepIntoSource(state);
    renderDbg(state);
  });
  $("btnDbgStepOut").addEventListener("click", () => {
    if (!state.trace) return;
    stepOutSource(state);
    renderDbg(state);
  });
  $("btnDbgOpcodePrev").addEventListener("click", () => {
    if (!state.trace) return;
    stepOpcode(state, -1);
    renderDbg(state);
  });
  $("btnDbgOpcodeNext").addEventListener("click", () => {
    if (!state.trace) return;
    stepOpcode(state, +1);
    renderDbg(state);
  });
  $("btnDbgContinue").addEventListener("click", async () => {
    if (!state.trace) {
      await runTrace(state);
      return;
    }
    continueExecution(state);
    renderDbg(state);
  });
  // Restart button - go back to step 0
  $("btnDbgRestart").addEventListener("click", () => {
    if (!state.trace) return;
    resetDbgCursor(state);
    renderDbg(state);
    scrollEditorToActive(state);
  });
  // Stop button - clear the trace
  $("btnDbgStop").addEventListener("click", () => {
    state.trace = null;
    renderDbg(state);
    renderEditorGutter(state);
    renderContractMeta(state);
    updateRunButton(state);
    setStatus("stopped", "");
  });
  // Keybindings
  window.addEventListener("keydown", async (e) => {
    if (e.key === "F5") {
      e.preventDefault();
      if (!state.trace) {
        await runTrace(state);
      } else {
        continueExecution(state);
        renderDbg(state);
      }
      return;
    }

    // Source-level stepping bindings (when a trace exists)
    if (!state.trace) return;
    const k = e.key;
    if (k !== "F10" && k !== "F11") return;
    if (isTextInput(e.target)) e.target.blur();

    if (k === "F10") {
      stepOverSource(state);
      renderDbg(state);
      e.preventDefault();
    } else {
      stepIntoSource(state);
      renderDbg(state);
      e.preventDefault();
    }
  });

  // Initial outline (also triggers first run + sigscript)
  await refreshOutline(state, { reason: "init" });
}

main().catch((err) => {
  console.error(err);
  document.body.innerHTML = `<pre style="padding:16px;font-family:ui-monospace,monospace;">Failed to load: ${escapeHtml(
    String(err && err.message ? err.message : err)
  )}</pre>`;
});
