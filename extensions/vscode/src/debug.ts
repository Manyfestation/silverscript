import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import {
  readSidecar,
  inferScriptPath,
  parseContractModel,
  defaultsFromParams,
} from "./contractModel";

function stringifyLaunchArg(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value) || (value !== null && typeof value === "object")) {
    return JSON.stringify(value);
  }
  return String(value);
}

// ── Adapter Factory ────────────────────────────────────────────────

class SilverScriptDebugAdapterFactory
  implements vscode.DebugAdapterDescriptorFactory
{
  constructor(
    private readonly ctx: vscode.ExtensionContext,
    private readonly out: vscode.OutputChannel,
  ) {}

  createDebugAdapterDescriptor(): vscode.ProviderResult<vscode.DebugAdapterDescriptor> {
    const root = path.resolve(this.ctx.extensionPath, "..", "..");
    const bin = path.join(
      root,
      "target",
      "debug",
      process.platform === "win32"
        ? "debugger-dap.exe"
        : "debugger-dap",
    );
    if (!fs.existsSync(bin)) {
      throw new Error(
        `Adapter not found: ${bin}. Run: cargo build -p debugger-dap`,
      );
    }
    this.out.appendLine(`[debug] launching ${bin}`);
    return new vscode.DebugAdapterExecutable(bin, [], {
      cwd: root,
    });
  }
}

// ── Config Provider ────────────────────────────────────────────────

class SilverScriptConfigProvider
  implements vscode.DebugConfigurationProvider
{
  async resolveDebugConfiguration(
    _folder: vscode.WorkspaceFolder | undefined,
    config: vscode.DebugConfiguration,
  ): Promise<vscode.DebugConfiguration | null | undefined> {
    if (
      config.type !== "silverscript" ||
      config.request !== "launch"
    )
      {return config;}

    // Expand ${file} in path fields
    for (const key of ["testFile", "scriptPath"] as const) {
      if (
        typeof config[key] === "string" &&
        (config[key] as string).includes("${file}")
      ) {
        const active =
          vscode.window.activeTextEditor?.document.uri.fsPath;
        if (!active) {
          vscode.window.showErrorMessage(
            "No active file to resolve ${file}.",
          );
          return null;
        }
        config[key] = (config[key] as string).replaceAll(
          "${file}",
          active,
        );
      }
    }

    // Test-case flow: pick test name if not specified
    if (
      typeof config.testFile === "string" &&
      (config.testFile as string).trim()
    ) {
      if (!config.testName) {
        const sidecar = await readSidecar(
          (config.testFile as string).trim(),
        );
        const names = (sidecar.tests ?? [])
          .map((t) => t.name)
          .filter(Boolean);
        if (!names.length) {
          vscode.window.showErrorMessage(
            `No tests in ${config.testFile}`,
          );
          return undefined;
        }
        const picked = await vscode.window.showQuickPick(
          names,
          { title: "Select test case" },
        );
        if (!picked) {return undefined;}
        config.testName = picked;
      }
      config.scriptPath ??= inferScriptPath(
        (config.testFile as string).trim(),
      );
      return config;
    }

    // Direct script flow — auto-detect from contract signature
    if (!config.scriptPath) {
      const doc = vscode.window.activeTextEditor?.document;
      if (doc?.languageId === "silverscript")
        {config.scriptPath = doc.uri.fsPath;}
    }

    if (config.scriptPath && typeof config.scriptPath === "string") {
      try {
        const source = fs.readFileSync(config.scriptPath, "utf8");
        const model = parseContractModel(source);

        if (
          !Array.isArray(config.constructorArgs) ||
          !(config.constructorArgs as unknown[]).length
        ) {
          config.constructorArgs = defaultsFromParams(
            model.constructorParams,
          ).map(stringifyLaunchArg);
        }

        if (!config.function && model.entrypoints.length > 0) {
          config.function = model.entrypoints[0].name;
        }

        if (
          config.function &&
          (!Array.isArray(config.args) ||
            !(config.args as unknown[]).length)
        ) {
          const ep = model.entrypoints.find(
            (e) => e.name === config.function,
          );
          if (ep) {
            config.args = defaultsFromParams(ep.params).map(stringifyLaunchArg);
          }
        }
      } catch {
        // If we can't parse, fall through with whatever config has
      }
    }

    config.stopOnEntry ??= true;

    return config;
  }
}

// ── Registration ───────────────────────────────────────────────────

export function registerSilverScriptDebugger(
  ctx: vscode.ExtensionContext,
): void {
  const out = vscode.window.createOutputChannel(
    "SilverScript Debugger",
  );
  const quickRunState = new Map<string, {
    failed: boolean;
    errorText?: string;
    functionName: string;
  }>();

  const summarizeError = (text: string | undefined): string | undefined => {
    if (!text) {return undefined;}
    const lines = text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    if (!lines.length) {return undefined;}
    return lines.slice(0, 3).join(" | ");
  };

  ctx.subscriptions.push(out);

  ctx.subscriptions.push(
    vscode.debug.registerDebugAdapterDescriptorFactory(
      "silverscript",
      new SilverScriptDebugAdapterFactory(ctx, out),
    ),
  );
  ctx.subscriptions.push(
    vscode.debug.registerDebugConfigurationProvider(
      "silverscript",
      new SilverScriptConfigProvider(),
    ),
  );
  ctx.subscriptions.push(
    vscode.debug.registerDebugAdapterTrackerFactory(
      "silverscript",
      {
        createDebugAdapterTracker: (session) => {
          const isQuickRun = session.configuration?._silverscriptQuickRun === true;
          if (isQuickRun) {
            quickRunState.set(session.id, {
              failed: false,
              errorText: undefined,
              functionName: String(session.configuration?.function ?? "entrypoint"),
            });
          }

          return {
          onWillStartSession: () =>
            out.appendLine("[debug] session starting"),
          onDidSendMessage: (message: unknown) => {
            if (!isQuickRun || !message || typeof message !== "object") {
              return;
            }

            const payload = message as {
              type?: string;
              event?: string;
              body?: { reason?: string; text?: string; category?: string; output?: string };
            };
            const state = quickRunState.get(session.id);
            if (!state) {
              return;
            }

            if (
              payload.type === "event" &&
              payload.event === "stopped" &&
              payload.body?.reason === "exception"
            ) {
              state.failed = true;
              state.errorText = summarizeError(payload.body.text) ?? state.errorText;
            }

            if (
              payload.type === "event" &&
              payload.event === "output" &&
              payload.body?.category === "stderr"
            ) {
              const summary = summarizeError(payload.body.output);
              if (summary) {
                state.failed = true;
                state.errorText = summary;
              }
            }
          },
          onError: (e: Error) =>
            out.appendLine(`[debug] error: ${e}`),
          onExit: (code: number | undefined, signal: string | undefined) => {
            out.appendLine(
              `[debug] exit: code=${code}, signal=${signal}`,
            );

            if (!isQuickRun) {
              return;
            }

            const state = quickRunState.get(session.id);
            quickRunState.delete(session.id);
            if (!state) {
              return;
            }

            if (state.failed) {
              vscode.window.showErrorMessage(
                state.errorText
                  ? `Run failed (${state.functionName}): ${state.errorText}`
                  : `Run failed (${state.functionName}). See Debug Console for details.`,
              );
            } else {
              vscode.window.showInformationMessage(
                `Run passed (${state.functionName}).`,
              );
            }
          },
        };
        },
      },
    ),
  );
}
