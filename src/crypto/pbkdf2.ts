import type { VaultInputs } from '../types/vault';

const encoder = new TextEncoder();

export const PBKDF2_ITERATIONS = 600_000;

export interface SeedDerivationResult {
  seed: Uint8Array;
  salt: Uint8Array;
  iterations: number;
  usedWorker: boolean;
  warning?: string;
}

/**
 * Derives 32 bytes of seed material from master passphrase + site context.
 * Per NIST SP 800-132 §5.3.
 */
export async function deriveSeeds(inputs: VaultInputs): Promise<Uint8Array> {
  const saltString = `${inputs.service}\0${inputs.username}\0${inputs.version}`;
  const saltHash = await crypto.subtle.digest('SHA-256', encoder.encode(saltString));

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(inputs.masterPassphrase),
    'PBKDF2',
    false,
    ['deriveBits'],
  );

  const derived = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: new Uint8Array(saltHash),
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    256,
  );

  return new Uint8Array(derived);
}

export async function deriveSeedsWithProgress(
  inputs: VaultInputs,
  onProgress: (pct: number) => void,
): Promise<SeedDerivationResult> {
  const saltString = `${inputs.service}\0${inputs.username}\0${inputs.version}`;
  const saltHash = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(saltString)));

  if (typeof Worker !== 'undefined') {
    try {
      const result = await deriveInWorker(inputs, onProgress);
      return {
        ...result,
        iterations: PBKDF2_ITERATIONS,
        usedWorker: true,
      };
    } catch {
      // Fall back to main thread if workers are unavailable or blocked.
    }
  }

  onProgress(5);
  const seed = await deriveSeeds(inputs);
  onProgress(100);

  return {
    seed,
    salt: saltHash,
    iterations: PBKDF2_ITERATIONS,
    usedWorker: false,
    warning: 'PBKDF2 worker unavailable; derivation ran on the main thread.',
  };
}

function deriveInWorker(
  inputs: VaultInputs,
  onProgress: (pct: number) => void,
): Promise<{ seed: Uint8Array; salt: Uint8Array }> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./pbkdf2.worker.ts', import.meta.url), { type: 'module' });

    worker.onmessage = (event: MessageEvent): void => {
      const data = event.data as
        | { type: 'progress'; pct: number }
        | { type: 'done'; seed: number[]; salt: number[] }
        | { type: 'error'; message: string };

      if (data.type === 'progress') {
        onProgress(data.pct);
        return;
      }

      if (data.type === 'error') {
        worker.terminate();
        reject(new Error(data.message));
        return;
      }

      worker.terminate();
      resolve({
        seed: new Uint8Array(data.seed),
        salt: new Uint8Array(data.salt),
      });
    };

    worker.onerror = (): void => {
      worker.terminate();
      reject(new Error('PBKDF2 worker failed to initialize.'));
    };

    worker.postMessage({
      masterPassphrase: inputs.masterPassphrase,
      service: inputs.service,
      username: inputs.username,
      version: inputs.version,
      iterations: PBKDF2_ITERATIONS,
    });
  });
}
