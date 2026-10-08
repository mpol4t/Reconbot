import fs from "node:fs";
import path from "node:path";

export function pythonExecutable(repoRoot: string): string {
  const configured = process.env.RECONBOT_PYTHON?.trim();
  if (configured) return configured;
  const bundled = path.join(process.resourcesPath || "", "backend", "reconbot-backend");
  if (fs.existsSync(bundled)) return bundled;
  const local = path.join(repoRoot, ".venv", process.platform === "win32" ? "Scripts" : "bin", process.platform === "win32" ? "python.exe" : "python");
  return fs.existsSync(local) ? local : "python3";
}
