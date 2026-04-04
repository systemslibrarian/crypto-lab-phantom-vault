import { derivePassword } from '../derive/pipeline';
import type { VaultInputs } from '../types/vault';

export interface ProofController {
  element: HTMLElement;
  runProof: (inputs: VaultInputs) => Promise<void>;
  setBusy: (busy: boolean) => void;
}

function requireNode<T extends Element>(parent: ParentNode, selector: string): T {
  const node = parent.querySelector<T>(selector);
  if (!node) {
    throw new Error(`Missing proof node: ${selector}`);
  }
  return node;
}

export function createProof(): ProofController {
  const wrapper = document.createElement('section');
  wrapper.className = 'panel';

  wrapper.innerHTML = `
    <h2 class="panel-title">Prove It</h2>
    <p class="helper-text">Determinism is the feature. Same inputs always produce the same password.</p>
    <div class="proof-grid">
      <p><strong>Run 1:</strong> <span id="proof-run1">-</span></p>
      <p><strong>Run 2:</strong> <span id="proof-run2">-</span></p>
    </div>
    <p id="proof-result" class="proof-result" aria-live="polite">Run proof to compare two derivations.</p>
  `;

  const run1 = requireNode<HTMLElement>(wrapper, '#proof-run1');
  const run2 = requireNode<HTMLElement>(wrapper, '#proof-run2');
  const result = requireNode<HTMLElement>(wrapper, '#proof-result');

  let busy = false;

  function setBusy(next: boolean): void {
    busy = next;
  }

  async function runProof(inputs: VaultInputs): Promise<void> {
    if (busy) {
      return;
    }

    result.textContent = 'Running deterministic proof...';
    const first = await derivePassword(inputs, () => {
      // Progress in proof is intentionally hidden to keep panel concise.
    });
    const second = await derivePassword(inputs, () => {
      // Progress in proof is intentionally hidden to keep panel concise.
    });

    run1.textContent = first.password;
    run2.textContent = second.password;
    result.textContent = first.password === second.password ? '✅ MATCH' : '❌ MISMATCH';
  }

  return {
    element: wrapper,
    runProof,
    setBusy,
  };
}
