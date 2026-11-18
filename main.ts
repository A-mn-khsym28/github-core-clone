import { createApp } from './app.ts';

const ENV_ORIGIN = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (!ENV_ORIGIN) {
  process.stderr.write('[forge] Missing MAKEFUN_ENV_URL environment variable\n');
  process.exit(1);
}

const CALL_TIMEOUT_MS = 30_000;
const INITIAL_BACKOFF_MS = 200;
const MAX_BACKOFF_MS = 2_000;

function pause(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function computeBackoff(step: number): number {
  return Math.min(MAX_BACKOFF_MS, INITIAL_BACKOFF_MS * 2 ** Math.min(step, 6));
}

async function notifyPort(port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const response = await fetch(`${ENV_ORIGIN}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(CALL_TIMEOUT_MS),
      });
      if (response.status === 200 || response.status === 409) {
        return;
      }
      if (response.status === 400 || response.status === 405) {
        throw new Error(`Registration rejected with HTTP ${response.status}: ${await response.text()}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('Registration rejected with HTTP ')) {
        throw err;
      }
    }
    await pause(computeBackoff(attempt));
  }
}

async function pollUntilComplete(): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const response = await fetch(`${ENV_ORIGIN}/done`, {
        signal: AbortSignal.timeout(CALL_TIMEOUT_MS),
      });
      if (response.ok) {
        const payload = (await response.json()) as { done?: unknown };
        if (payload.done === true) {
          return;
        }
      }
    } catch {
      // Continue polling while the benchmark suite is active.
    }
    await pause(computeBackoff(attempt));
  }
}

async function bootstrapForge(): Promise<void> {
  const server = createApp();
  const shutdown = (): void => {
    server.close();
    process.exit(0);
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });

  const bound = server.address();
  if (bound === null || typeof bound === 'string') {
    throw new Error('Failed to bind ephemeral TCP port');
  }

  process.stdout.write(`[forge] Bound to port ${bound.port}\n`);
  await notifyPort(bound.port);
  process.stdout.write('[forge] Registered with environment; awaiting completion\n');

  await pollUntilComplete();
  server.close();
  process.stdout.write('[forge] Trial complete\n');
}

try {
  await bootstrapForge();
  process.exit(0);
} catch (err) {
  process.stderr.write(`[forge] Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
