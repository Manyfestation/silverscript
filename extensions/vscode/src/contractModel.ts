import * as fs from "fs/promises";
import * as path from "path";

// ── Types ──────────────────────────────────────────────────────────

export type ContractParam = { name: string; type: string };
export type Entrypoint = { name: string; params: ContractParam[] };
export type ContractModel = {
  name: string;
  constructorParams: ContractParam[];
  entrypoints: Entrypoint[];
};

export type SidecarTestCase = {
  name: string;
  function: string;
  constructor_args?: unknown[];
  args?: unknown[];
  expect?: "pass" | "fail";
  tx?: unknown;
};

export type SidecarTestFile = { tests?: SidecarTestCase[] };

// ── Path helpers ───────────────────────────────────────────────────

export function inferSidecarPath(scriptPath: string): string {
  const base = path.basename(scriptPath, path.extname(scriptPath));
  return path.join(path.dirname(scriptPath), `${base}.test.json`);
}

export function inferScriptPath(sidecarPath: string): string {
  const name = path.basename(sidecarPath);
  if (!name.endsWith(".test.json")) {return sidecarPath;}
  return path.join(
    path.dirname(sidecarPath),
    `${name.slice(0, -".test.json".length)}.sil`,
  );
}

// ── Contract parsing ───────────────────────────────────────────────

function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "");
}

function parseParams(raw: string): ContractParam[] {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((part, i) => {
      const [t, n] = part.split(/\s+/).filter(Boolean);
      return { type: t ?? "int", name: n ?? `arg${i}` };
    });
}

export function parseContractModel(source: string): ContractModel {
  const clean = stripComments(source);
  const hdr = clean.match(
    /contract\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/m,
  );
  const name = hdr?.[1] ?? "Unknown";
  const constructorParams = hdr?.[2]?.trim()
    ? parseParams(hdr[2])
    : [];
  const entrypoints: Entrypoint[] = [];
  const re =
    /entrypoint\s+function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/g;
  for (let m; (m = re.exec(clean)); ) {
    entrypoints.push({ name: m[1], params: parseParams(m[2]) });
  }
  return { name, constructorParams, entrypoints };
}

// ── Type-aware defaults ────────────────────────────────────────────

function hex(n: number): string {
  return `0x${"00".repeat(Math.max(0, n))}`;
}

export function defaultForType(t: string): unknown {
  const s = t.trim();
  if (s.endsWith("[]")) {return [];}
  switch (s) {
    case "int":
      return 0;
    case "bool":
      return false;
    case "string":
      return "";
    case "byte":
      return hex(1);
    case "bytes":
      return hex(0);
    case "pubkey":
      return hex(32);
    case "sig":
      return hex(65);
    case "datasig":
      return hex(64);
  }
  let m = s.match(/^bytes(\d+)$/);
  if (m) {return hex(Number(m[1]));}
  m = s.match(/^byte\[(\d+)\]$/);
  if (m) {return hex(Number(m[1]));}
  return 0;
}

export function defaultsFromParams(params: ContractParam[]): unknown[] {
  return params.map((p) => defaultForType(p.type));
}

// ── Sidecar I/O ────────────────────────────────────────────────────

export async function readSidecar(
  p: string,
): Promise<SidecarTestFile> {
  try {
    return JSON.parse(
      await fs.readFile(p, "utf8"),
    ) as SidecarTestFile;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT")
      {return { tests: [] };}
    throw e;
  }
}

export async function writeSidecar(
  p: string,
  data: SidecarTestFile,
): Promise<void> {
  await fs.writeFile(
    p,
    JSON.stringify(data, null, 2) + "\n",
    "utf8",
  );
}
