import * as vscode from "vscode";
import {
  parseContractModel,
  inferSidecarPath,
  readSidecar,
} from "./contractModel";

// ── Provider ───────────────────────────────────────────────────────

class SilverScriptCodeLensProvider implements vscode.CodeLensProvider {
  private _onChange = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._onChange.event;

  refresh(): void {
    this._onChange.fire();
  }

  async provideCodeLenses(
    doc: vscode.TextDocument,
  ): Promise<vscode.CodeLens[]> {
    if (doc.languageId !== "silverscript") {return [];}
    const source = doc.getText();
    const model = parseContractModel(source);
    const sidecar = await readSidecar(
      inferSidecarPath(doc.uri.fsPath),
    );
    const tests = sidecar.tests ?? [];
    const lenses: vscode.CodeLens[] = [];

    for (const ep of model.entrypoints) {
      const m = new RegExp(
        `entrypoint\\s+function\\s+${ep.name}\\s*\\(`,
      ).exec(source);
      if (!m) {continue;}

      const range = new vscode.Range(
        doc.positionAt(m.index),
        doc.positionAt(m.index),
      );
      const count = tests.filter(
        (t) => t.function === ep.name,
      ).length;

      lenses.push(
        lens(
          range,
          "$(settings-gear) Configure & Run",
          "silverscript.codelens.configure",
          [doc.uri, ep.name],
        ),
      );

      if (count > 0) {
        lenses.push(
          lens(
            range,
            `$(beaker) ${count} test${count !== 1 ? "s" : ""}`,
            "testing.runAll",
            [],
          ),
        );
      }
    }

    return lenses;
  }
}

function lens(
  range: vscode.Range,
  title: string,
  command: string,
  args: unknown[],
): vscode.CodeLens {
  return new vscode.CodeLens(range, {
    title,
    command,
    arguments: args,
  });
}

// ── Registration ───────────────────────────────────────────────────

export function registerSilverScriptCodeLens(
  ctx: vscode.ExtensionContext,
): void {
  const provider = new SilverScriptCodeLensProvider();
  ctx.subscriptions.push(
    vscode.languages.registerCodeLensProvider(
      { language: "silverscript" },
      provider,
    ),
  );
  ctx.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(() => provider.refresh()),
  );

  // ⚙ Configure — open guided panel for this entrypoint
  ctx.subscriptions.push(
    vscode.commands.registerCommand(
      "silverscript.codelens.configure",
      async (uri: vscode.Uri, fn: string) => {
        await vscode.commands.executeCommand(
          "silverscript.debug.configureLaunch",
          uri,
          fn,
        );
      },
    ),
  );

  // Compatibility alias: Debug opens the same guided panel
  ctx.subscriptions.push(
    vscode.commands.registerCommand(
      "silverscript.codelens.debug",
      async (uri: vscode.Uri, fn: string) => {
        await vscode.commands.executeCommand(
          "silverscript.debug.configureLaunch",
          uri,
          fn,
        );
      },
    ),
  );

  // Compatibility alias: Test opens the same guided panel
  ctx.subscriptions.push(
    vscode.commands.registerCommand(
      "silverscript.codelens.addTest",
      async (uri: vscode.Uri, fn: string) => {
        await vscode.commands.executeCommand(
          "silverscript.debug.configureLaunch",
          uri,
          fn,
        );
      },
    ),
  );

  // Compatibility alias: Scenario opens the same guided panel
  ctx.subscriptions.push(
    vscode.commands.registerCommand(
      "silverscript.codelens.addScenario",
      async (uri: vscode.Uri, fn: string) => {
        await vscode.commands.executeCommand(
          "silverscript.debug.configureLaunch",
          uri,
          fn,
        );
      },
    ),
  );
}
