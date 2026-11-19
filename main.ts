import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(fileURLToPath(import.meta.url));

function resolveBinary(): string {
  const candidates =
    process.arch === 'arm64'
      ? ['forge-linux-arm64', 'forge-linux-amd64']
      : ['forge-linux-amd64'];
  for (const name of candidates) {
    const full = join(rootDir, name);
    if (existsSync(full)) {
      return full;
    }
  }
  throw new Error(`No compiled forge binary found in ${rootDir} for ${process.platform}/${process.arch}`);
}

const binPath = resolveBinary();
const child = spawn(binPath, [], {
  stdio: 'inherit',
  env: process.env,
});

const forwardSignal = (sig: NodeJS.Signals): void => {
  if (!child.killed) {
    child.kill(sig);
  }
};

process.once('SIGTERM', () => forwardSignal('SIGTERM'));
process.once('SIGINT', () => forwardSignal('SIGINT'));

child.once('error', (err) => {
  process.stderr.write(`[forge-launcher] Failed to start ${binPath}: ${err.message}\n`);
  process.exit(1);
});

child.once('exit', (code, signal) => {
  if (signal) {
    process.exit(0);
  }
  process.exit(code ?? 0);
});
