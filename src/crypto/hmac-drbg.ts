import type { DRBGState } from '../types/vault';

const OUTLEN = 32;

export interface InternalDRBGState {
  K: Uint8Array;
  V: Uint8Array;
  reseedCounter: number;
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const merged = new Uint8Array(total);
  let offset = 0;

  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }

  return merged;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

export function snapshotState(state: InternalDRBGState): DRBGState {
  return {
    K: toHex(state.K),
    V: toHex(state.V),
    reseedCounter: state.reseedCounter,
  };
}

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const keyData = new Uint8Array(key);
  const payload = new Uint8Array(data);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, payload));
}

/**
 * HMAC_DRBG_Update per NIST SP 800-90A Rev 1 §10.1.2.2
 */
export async function hmacDrbgUpdate(
  providedData: Uint8Array | null,
  K: Uint8Array,
  V: Uint8Array,
): Promise<{ K: Uint8Array; V: Uint8Array }> {
  const data = providedData ?? new Uint8Array(0);

  let nextK = await hmac(K, concatBytes(V, new Uint8Array([0x00]), data));
  let nextV = await hmac(nextK, V);

  if (data.length !== 0) {
    nextK = await hmac(nextK, concatBytes(nextV, new Uint8Array([0x01]), data));
    nextV = await hmac(nextK, nextV);
  }

  return { K: nextK, V: nextV };
}

/**
 * HMAC_DRBG_Instantiate per NIST SP 800-90A Rev 1 §10.1.2.3
 */
export async function hmacDrbgInstantiate(
  entropyInput: Uint8Array,
  nonce: Uint8Array,
  personalizationString: Uint8Array,
): Promise<{ state: InternalDRBGState; snapshot: DRBGState }> {
  const seedMaterial = concatBytes(entropyInput, nonce, personalizationString);
  const K = new Uint8Array(OUTLEN);
  const V = new Uint8Array(OUTLEN).fill(0x01);
  const updated = await hmacDrbgUpdate(seedMaterial, K, V);

  const state: InternalDRBGState = {
    K: updated.K,
    V: updated.V,
    reseedCounter: 1,
  };

  return {
    state,
    snapshot: snapshotState(state),
  };
}

/**
 * HMAC_DRBG_Generate per NIST SP 800-90A Rev 1 §10.1.2.5
 */
export async function hmacDrbgGenerate(
  state: InternalDRBGState,
  requestedBytes: number,
): Promise<{ bytes: Uint8Array; state: InternalDRBGState; snapshot: DRBGState }> {
  if (requestedBytes <= 0) {
    throw new Error('Requested bytes must be greater than zero.');
  }

  const output = new Uint8Array(requestedBytes);
  let produced = 0;
  let V = state.V;

  while (produced < requestedBytes) {
    V = await hmac(state.K, V);
    const available = Math.min(V.length, requestedBytes - produced);
    output.set(V.slice(0, available), produced);
    produced += available;
  }

  const updated = await hmacDrbgUpdate(null, state.K, V);

  const nextState: InternalDRBGState = {
    K: updated.K,
    V: updated.V,
    reseedCounter: state.reseedCounter + 1,
  };

  return {
    bytes: output,
    state: nextState,
    snapshot: snapshotState(nextState),
  };
}
