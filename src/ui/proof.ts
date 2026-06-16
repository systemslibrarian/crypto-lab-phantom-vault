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
    <p class="helper-text">
      Two claims, demonstrated live: the same inputs always reproduce the same password
      (determinism), and bumping the version produces a different one (rotation).
    </p>
    <table class="proof-table">
      <caption class="sr-only">Comparison of derivations proving determinism and rotation</caption>
      <thead>
        <tr>
          <th scope="col">Run</th>
          <th scope="col">Inputs</th>
          <th scope="col">Password</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <th scope="row">1</th>
          <td id="proof-label1">same inputs</td>
          <td><span class="proof-pw" id="proof-run1">—</span></td>
        </tr>
        <tr>
          <th scope="row">2</th>
          <td id="proof-label2">same inputs again</td>
          <td><span class="proof-pw" id="proof-run2">—</span></td>
        </tr>
        <tr>
          <th scope="row">3</th>
          <td id="proof-label3">version + 1</td>
          <td><span class="proof-pw" id="proof-run3">—</span></td>
        </tr>
      </tbody>
    </table>
    <p id="proof-result" class="proof-result" aria-live="polite" role="status">Run proof to compare three derivations.</p>
  `;

  const run1 = requireNode<HTMLElement>(wrapper, '#proof-run1');
  const run2 = requireNode<HTMLElement>(wrapper, '#proof-run2');
  const run3 = requireNode<HTMLElement>(wrapper, '#proof-run3');
  const label3 = requireNode<HTMLElement>(wrapper, '#proof-label3');
  const result = requireNode<HTMLElement>(wrapper, '#proof-result');

  let busy = false;

  function setBusy(next: boolean): void {
    busy = next;
  }

  async function runProof(inputs: VaultInputs): Promise<void> {
    if (busy) {
      return;
    }

    const silent = (): void => {
      // Progress in proof is intentionally hidden to keep the panel concise.
    };

    result.textContent = 'Running determinism + rotation proof…';
    run1.textContent = '…';
    run2.textContent = '…';
    run3.textContent = '…';

    const first = await derivePassword(inputs, silent);
    const second = await derivePassword(inputs, silent);

    const rotated: VaultInputs = { ...inputs, version: inputs.version + 1 };
    label3.textContent = `version ${rotated.version}`;
    const third = await derivePassword(rotated, silent);

    run1.textContent = first.password;
    run2.textContent = second.password;
    run3.textContent = third.password;

    const deterministic = first.password === second.password;
    const rotates = third.password !== first.password;

    if (deterministic && rotates) {
      result.textContent = '✅ Determinism holds (Run 1 = Run 2) and rotation works (Run 3 differs).';
    } else if (!deterministic) {
      result.textContent = '❌ Determinism broken: identical inputs produced different passwords.';
    } else {
      result.textContent = '❌ Rotation failed: a new version produced the same password.';
    }
  }

  return {
    element: wrapper,
    runProof,
    setBusy,
  };
}
