import { buildCharset, hasRequiredCharacterClasses, mapBytesToPassword } from '../crypto/charset';
import { hmacDrbgGenerate, hmacDrbgInstantiate, type InternalDRBGState } from '../crypto/hmac-drbg';
import { deriveSeedsWithProgress } from '../crypto/pbkdf2';
import type { DerivationResult, DRBGState, VaultInputs } from '../types/vault';

const encoder = new TextEncoder();
const PERSONALIZATION = encoder.encode('phantom-vault:v1');

export type PipelineStep = 'stretching' | 'instantiating' | 'generating' | 'mapping' | 'complete';

export interface PipelineMeta {
  warning?: string;
  attempts: number;
}

export async function derivePassword(
  inputs: VaultInputs,
  onProgress: (step: PipelineStep, pct: number) => void,
): Promise<DerivationResult & { meta: PipelineMeta }> {
  if (!inputs.masterPassphrase.trim()) {
    throw new Error('Master passphrase is required.');
  }

  // The core validates its own boundaries rather than trusting the form.
  // `version < 1` alone let NaN and fractions through (NaN < 1 is false), and
  // a fractional length reached the mapper, whose `while (chars.length <
  // length)` loop then emitted ceil(length) characters — a 20.5 in the form's
  // number input produced a 21-character password labelled 20.5.
  if (!Number.isInteger(inputs.version) || inputs.version < 1) {
    throw new Error('Version must be a whole number of at least 1.');
  }

  if (!Number.isInteger(inputs.length) || inputs.length < 8 || inputs.length > 64) {
    throw new Error('Length must be a whole number between 8 and 64.');
  }

  // Context fields feed a NUL-separated salt string; a NUL inside a field
  // would make two different contexts encode identically.
  if (inputs.service.includes('\0') || inputs.username.includes('\0')) {
    throw new Error('Service and username must not contain NUL characters.');
  }

  onProgress('stretching', 0);
  const seedResult = await deriveSeedsWithProgress(inputs, (pct) => onProgress('stretching', pct));
  onProgress('instantiating', 10);

  const instantiate = await hmacDrbgInstantiate(seedResult.seed, seedResult.salt, PERSONALIZATION);
  const snapshots: DRBGState[] = [instantiate.snapshot];

  let state: InternalDRBGState = instantiate.state;
  let bytesGenerated = 0;

  onProgress('instantiating', 100);
  onProgress('generating', 25);

  const initialRequest = Math.max(inputs.length * 2, 32);
  const generated = await hmacDrbgGenerate(state, initialRequest);
  state = generated.state;
  snapshots.push(generated.snapshot);
  bytesGenerated += generated.bytes.length;
  let candidateBytes = generated.bytes;

  onProgress('generating', 100);
  onProgress('mapping', 10);

  const charset = buildCharset(inputs.charset);
  let rejectionCount = 0;
  let attempts = 0;
  // Genuine DRBG byte values examined while mapping, captured so the
  // distribution exhibit plots the real run (never a fabricated histogram).
  const sampledBytes: number[] = [];
  const recordBytes = (bytes: Uint8Array): void => {
    for (const value of bytes) {
      sampledBytes.push(value);
    }
  };
  recordBytes(candidateBytes);

  while (attempts < 16) {
    attempts += 1;

    const mapped = await mapBytesToPassword(candidateBytes, charset, inputs.length, async () => {
      const more = await hmacDrbgGenerate(state, Math.max(inputs.length, 32));
      state = more.state;
      snapshots.push(more.snapshot);
      bytesGenerated += more.bytes.length;
      recordBytes(more.bytes);
      return more.bytes;
    });

    rejectionCount += mapped.rejectionCount;

    if (hasRequiredCharacterClasses(mapped.password, inputs.charset)) {
      onProgress('mapping', 100);
      onProgress('complete', 100);

      const meta: PipelineMeta = { attempts };
      if (seedResult.warning) {
        meta.warning = seedResult.warning;
      }

      return {
        password: mapped.password,
        drbgStates: snapshots,
        pbkdf2Iterations: seedResult.iterations,
        bytesGenerated,
        rejectionCount,
        sampledBytes,
        meta,
      };
    }

    const refresh = await hmacDrbgGenerate(state, initialRequest);
    state = refresh.state;
    snapshots.push(refresh.snapshot);
    bytesGenerated += refresh.bytes.length;
    recordBytes(refresh.bytes);
    candidateBytes = refresh.bytes;
  }

  throw new Error('Unable to satisfy character class coverage after multiple attempts.');
}
