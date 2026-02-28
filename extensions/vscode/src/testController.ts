import * as vscode from "vscode";
import * as path from "path";
import {
  readSidecar,
  writeSidecar,
  inferSidecarPath,
  inferScriptPath,
  parseContractModel,
  defaultForType,
  defaultsFromParams,
  ContractParam,
  SidecarTestCase,
} from "./contractModel";

// ── Types ──────────────────────────────────────────────────────────

type TestMeta = {
  sidecarUri: vscode.Uri;
  scriptPath: string;
  testName: string;
};

// ── Registration ───────────────────────────────────────────────────

export function registerSilverScriptTestController(
  ctx: vscode.ExtensionContext,
): void {
  const ctrl = vscode.tests.createTestController(
    "silverscriptTests",
    "SilverScript",
  );
  ctx.subscriptions.push(ctrl);

  const meta = new WeakMap<vscode.TestItem, TestMeta>();

  // ── Discovery ──────────────────────────────────────────────────

  const watcher =
    vscode.workspace.createFileSystemWatcher("**/*.test.json");
  ctx.subscriptions.push(watcher);

  async function loadFile(uri: vscode.Uri): Promise<void> {
    const sidecar = await readSidecar(uri.fsPath);
    const tests = sidecar.tests ?? [];
    if (!tests.length) {
      ctrl.items.delete(uri.toString());
      return;
    }

    const scriptPath = inferScriptPath(uri.fsPath);
    const file = ctrl.createTestItem(
      uri.toString(),
      path.basename(uri.fsPath, ".test.json"),
      uri,
    );
    for (const t of tests) {
      const item = ctrl.createTestItem(
        `${uri.toString()}::${t.name}`,
        t.name,
        uri,
      );
      item.description = `${t.function} · ${t.expect ?? "pass"}`;
      meta.set(item, {
        sidecarUri: uri,
        scriptPath,
        testName: t.name,
      });
      file.children.add(item);
    }
    ctrl.items.add(file);
  }

  async function discoverAll(): Promise<void> {
    const files = await vscode.workspace.findFiles(
      "**/*.test.json",
      "**/node_modules/**",
    );
    await Promise.all(files.map(loadFile));
  }

  watcher.onDidChange(loadFile);
  watcher.onDidCreate(loadFile);
  watcher.onDidDelete((uri) => ctrl.items.delete(uri.toString()));
  void discoverAll();

  // ── Run profile ────────────────────────────────────────────────

  ctrl.createRunProfile(
    "Run",
    vscode.TestRunProfileKind.Run,
    async (request, token) => {
      const run = ctrl.createTestRun(request);
      for (const item of leafItems(request, ctrl)) {
        if (token.isCancellationRequested) {break;}
        const m = meta.get(item);
        if (!m) {
          run.skipped(item);
          continue;
        }
        run.started(item);
        const t0 = Date.now();
        try {
          const r = await launchTest(m, token);
          if (r.passed) {run.passed(item, Date.now() - t0);}
          else {
            const msg = new vscode.TestMessage(r.error ?? "failed");
            // Parse location from the formatted failure report: "  --> file:line:col"
            const loc = parseFailureLocation(r.error, m.scriptPath);
            if (loc) {msg.location = loc;}
            run.failed(item, msg, Date.now() - t0);
          }
        } catch (e) {
          run.errored(
            item,
            new vscode.TestMessage(String(e)),
          );
        }
      }
      run.end();
    },
  );

  // ── Debug profile ─────────────────────────────────────────────

  ctrl.createRunProfile(
    "Debug",
    vscode.TestRunProfileKind.Debug,
    async (request) => {
      const item = leafItems(request, ctrl)[0];
      const m = item && meta.get(item);
      if (!m) {return;}
      const folder =
        vscode.workspace.getWorkspaceFolder(m.sidecarUri) ??
        vscode.workspace.workspaceFolders?.[0];
      await vscode.debug.startDebugging(folder, {
        type: "silverscript",
        request: "launch",
        name: `Debug: ${m.testName}`,
        testFile: m.sidecarUri.fsPath,
        testName: m.testName,
        scriptPath: m.scriptPath,
        stopOnEntry: true,
      });
    },
  );

  // ── Generate boundary tests ───────────────────────────────────

  ctx.subscriptions.push(
    vscode.commands.registerCommand(
      "silverscript.tests.generate",
      async () => {
        const editor = vscode.window.activeTextEditor;
        if (
          !editor ||
          editor.document.languageId !== "silverscript"
        ) {
          vscode.window.showErrorMessage(
            "Open a .sil file first.",
          );
          return;
        }

        const source = editor.document.getText();
        const model = parseContractModel(source);
        if (!model.entrypoints.length) {
          vscode.window.showErrorMessage(
            "No entrypoint functions found.",
          );
          return;
        }

        const picked =
          model.entrypoints.length === 1
            ? model.entrypoints[0]
            : (
                await vscode.window.showQuickPick(
                  model.entrypoints.map((e) => ({
                    label: e.name,
                    ep: e,
                  })),
                  { title: "Generate tests for?" },
                )
              )?.ep;
        if (!picked) {return;}

        const sp = inferSidecarPath(
          editor.document.uri.fsPath,
        );
        const existing = (await readSidecar(sp)).tests ?? [];
        const names = new Set(existing.map((t) => t.name));
        const generated = boundaryTests(
          picked.name,
          picked.params,
          defaultsFromParams(model.constructorParams),
        );
        const fresh = generated.filter(
          (t) => !names.has(t.name),
        );
        if (!fresh.length) {
          vscode.window.showInformationMessage(
            "All boundary tests already exist.",
          );
          return;
        }
        await writeSidecar(sp, {
          tests: [...existing, ...fresh],
        });
        vscode.window.showInformationMessage(
          `Generated ${fresh.length} test${fresh.length !== 1 ? "s" : ""} for ${picked.name}`,
        );
      },
    ),
  );
}

// ── Helpers ─────────────────────────────────────────────────────────

function leafItems(
  req: vscode.TestRunRequest,
  ctrl: vscode.TestController,
): vscode.TestItem[] {
  const out: vscode.TestItem[] = [];
  const excluded = new Set(req.exclude?.map((e) => e.id));
  const add = (item: vscode.TestItem) => {
    if (excluded.has(item.id)) {return;}
    if (item.children.size) {item.children.forEach(add);}
    else {out.push(item);}
  };
  if (req.include) {req.include.forEach(add);}
  else {ctrl.items.forEach(add);}
  return out;
}

/** Launch a debug session silently and resolve with pass/fail. */
function launchTest(
  m: TestMeta,
  token: vscode.CancellationToken,
): Promise<{ passed: boolean; error?: string }> {
  return new Promise((resolve) => {
    const id = `__run_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
    let error: string | undefined;
    let done = false;

    const finish = (r: { passed: boolean; error?: string }) => {
      if (done) {return;}
      done = true;
      d1.dispose();
      d2.dispose();
      d3.dispose();
      resolve(r);
    };

    const d1 =
      vscode.debug.registerDebugAdapterTrackerFactory(
        "silverscript",
        {
          createDebugAdapterTracker: (s) => {
            if (
              (
                s.configuration as Record<
                  string,
                  unknown
                >
              ).__runId !== id
            )
              {return undefined;}
            return {
              onDidSendMessage: (
                msg: Record<string, unknown>,
              ) => {
                if (
                  msg.type === "event" &&
                  msg.event === "stopped" &&
                  (
                    msg.body as {
                      reason?: string;
                      text?: string;
                    }
                  )?.reason === "exception"
                ) {
                  error =
                    (
                      msg.body as {
                        text?: string;
                      }
                    )?.text ?? "require() failed";
                  void vscode.debug.stopDebugging(s);
                } else if (
                  msg.type === "event" &&
                  msg.event === "output" &&
                  (msg.body as { category?: string })
                    ?.category === "stderr"
                ) {
                  // Prefer the richer stderr output (formatted failure report)
                  // over the stopped event text.
                  const output = (
                    msg.body as { output?: string }
                  )?.output?.trim();
                  if (output) {
                    error = output;
                  }
                }
              },
            };
          },
        },
      );

    const d2 = vscode.debug.onDidTerminateDebugSession(
      (s) => {
        if (
          (s.configuration as Record<string, unknown>)
            .__runId === id
        )
          {finish({ passed: !error, error });}
      },
    );

    const d3 = token.onCancellationRequested(() =>
      finish({ passed: false, error: "Cancelled" }),
    );

    const folder =
      vscode.workspace.getWorkspaceFolder(m.sidecarUri) ??
      vscode.workspace.workspaceFolders?.[0];
    void vscode.debug.startDebugging(
      folder,
      {
        type: "silverscript",
        request: "launch",
        name: id,
        __runId: id,
        testFile: m.sidecarUri.fsPath,
        testName: m.testName,
        scriptPath: m.scriptPath,
        stopOnEntry: false,
      },
      { noDebug: true },
    );
  });
}

/**
 * Parses a source location from a formatted failure report.
 * Looks for lines matching `  --> <filename>:<line>:<col>` or `  --> <line>:<col>`.
 */
function parseFailureLocation(
  errorText: string | undefined,
  scriptPath: string,
): vscode.Location | undefined {
  if (!errorText) {return undefined;}
  // Match "  --> filename:line:col" or "  --> line:col"
  const withFile = /-->\s+(.+):(\d+):(\d+)/.exec(errorText);
  if (withFile) {
    const [, filePart, lineStr, colStr] = withFile;
    const file = path.isAbsolute(filePart)
      ? filePart
      : path.resolve(path.dirname(scriptPath), filePart);
    const line = Math.max(0, parseInt(lineStr, 10) - 1);
    const col = Math.max(0, parseInt(colStr, 10) - 1);
    return new vscode.Location(
      vscode.Uri.file(file),
      new vscode.Position(line, col),
    );
  }
  // Fallback: "  --> line:col" (no filename)
  const noFile = /-->\s+(\d+):(\d+)/.exec(errorText);
  if (noFile) {
    const [, lineStr, colStr] = noFile;
    const line = Math.max(0, parseInt(lineStr, 10) - 1);
    const col = Math.max(0, parseInt(colStr, 10) - 1);
    return new vscode.Location(
      vscode.Uri.file(scriptPath),
      new vscode.Position(line, col),
    );
  }
  return undefined;
}

// ── Boundary test generation ────────────────────────────────────────

function boundaryTests(
  fn: string,
  params: ContractParam[],
  ctorDefaults: unknown[],
): SidecarTestCase[] {
  if (!params.length) {
    return [
      {
        name: `${fn}_no_args`,
        function: fn,
        constructor_args: ctorDefaults,
        args: [],
        expect: "pass",
      },
    ];
  }

  const val = (
    p: ContractParam,
    kind: "zero" | "one" | "neg" | "big",
  ): unknown => {
    if (p.type === "int") {
      switch (kind) {
        case "zero":
          return 0;
        case "one":
          return 1;
        case "neg":
          return -1;
        case "big":
          return 1000;
      }
    }
    if (p.type === "bool") {
      return kind !== "zero" && kind !== "neg";
    }
    return defaultForType(p.type);
  };

  const make = (
    suffix: string,
    args: unknown[],
  ): SidecarTestCase => ({
    name: `${fn}_${suffix}`,
    function: fn,
    constructor_args: ctorDefaults,
    args,
    expect: "pass",
  });

  const cases = [
    make(
      "zeros",
      params.map((p) => val(p, "zero")),
    ),
    make(
      "ones",
      params.map((p) => val(p, "one")),
    ),
    make(
      "negative",
      params.map((p) => val(p, "neg")),
    ),
    make(
      "large",
      params.map((p) => val(p, "big")),
    ),
  ];

  if (params.length >= 2) {
    cases.push(
      make(
        "mixed",
        params.map((p, i) => val(p, i === 0 ? "one" : "neg")),
      ),
    );
  }

  return cases;
}
