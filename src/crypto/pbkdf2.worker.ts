const encoder = new TextEncoder();

interface WorkerRequest {
  masterPassphrase: string;
  service: string;
  username: string;
  version: number;
  iterations: number;
}

interface WorkerProgressMessage {
  type: 'progress';
  pct: number;
}

interface WorkerDoneMessage {
  type: 'done';
  seed: number[];
  salt: number[];
}

interface WorkerErrorMessage {
  type: 'error';
  message: string;
}

function postProgress(pct: number): void {
  const payload: WorkerProgressMessage = { type: 'progress', pct };
  postMessage(payload);
}

self.onmessage = async (event: MessageEvent<WorkerRequest>): Promise<void> => {
  const request = event.data;
  const start = Date.now();
  let visualPct = 0;

  const progressTimer = setInterval(() => {
    const elapsed = Date.now() - start;
    const estimated = 2600;
    const computed = Math.min(95, Math.floor((elapsed / estimated) * 95));
    visualPct = Math.max(visualPct, computed);
    postProgress(visualPct);
  }, 80);

  try {
    const saltString = `${request.service}:${request.username}:${request.version}`;
    const saltHash = await crypto.subtle.digest('SHA-256', encoder.encode(saltString));

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(request.masterPassphrase),
      'PBKDF2',
      false,
      ['deriveBits'],
    );

    const derived = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: new Uint8Array(saltHash),
        iterations: request.iterations,
        hash: 'SHA-256',
      },
      keyMaterial,
      256,
    );

    postProgress(100);
    clearInterval(progressTimer);

    const donePayload: WorkerDoneMessage = {
      type: 'done',
      seed: Array.from(new Uint8Array(derived)),
      salt: Array.from(new Uint8Array(saltHash)),
    };

    postMessage(donePayload);
  } catch (error) {
    clearInterval(progressTimer);
    const message = error instanceof Error ? error.message : 'Unknown PBKDF2 worker error';
    const errorPayload: WorkerErrorMessage = { type: 'error', message };
    postMessage(errorPayload);
  }
};
