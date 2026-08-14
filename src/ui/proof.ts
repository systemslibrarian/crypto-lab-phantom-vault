import { derivePassword } from '../derive/pipeline';
import type { VaultInputs } from '../types/vault';

export interface ProofController {
  element: HTMLElement;
  runProof: (inputs: VaultInputs) => Promise<void>;
  setBusy: (busy: boolean) => void;
  /** Retire the four rows — they compare derivations of inputs now edited. */
  reset: () => void;
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
      Three claims, demonstrated live rather than asserted: the same inputs always reproduce
      the same password (<strong>determinism</strong>), bumping the version produces a different
      one (<strong>rotation</strong>), and changing the service or username produces a different
      one too (<strong>context separation</strong>).
    </p>
    <table class="proof-table">
      <caption class="sr-only">Comparison of derivations proving determinism, rotation, and context separation</caption>
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
        <tr>
          <th scope="row">4</th>
          <td id="proof-label4">different service</td>
          <td><span class="proof-pw" id="proof-run4">—</span></td>
        </tr>
      </tbody>
    </table>
    <p id="proof-result" class="proof-result" aria-live="polite" role="status">Run proof to compare four derivations.</p>
  `;

  const run1 = requireNode<HTMLElement>(wrapper, '#proof-run1');
  const run2 = requireNode<HTMLElement>(wrapper, '#proof-run2');
  const run3 = requireNode<HTMLElement>(wrapper, '#proof-run3');
  const run4 = requireNode<HTMLElement>(wrapper, '#proof-run4');
  const label3 = requireNode<HTMLElement>(wrapper, '#proof-label3');
  const label4 = requireNode<HTMLElement>(wrapper, '#proof-label4');
  const result = requireNode<HTMLElement>(wrapper, '#proof-result');

  // `running` is an internal reentrancy guard so a proof cannot overlap itself.
  // It is intentionally SEPARATE from the external setBusy() flag: main.ts marks
  // the whole derivation busy (to disable buttons) and *then* calls runProof, so
  // keying the guard off that external flag would make the proof always early-
  // return — leaving every row blank. Only concurrent runProof calls are blocked.
  let running = false;

  function setBusy(_next: boolean): void {
    // Retained for controller-API compatibility; button disabling lives in main.
  }

  async function runProof(inputs: VaultInputs): Promise<void> {
    if (running) {
      return;
    }
    running = true;
    try {

    const silent = (): void => {
      // Progress in proof is intentionally hidden to keep the panel concise.
    };

    result.textContent = 'Running determinism + rotation + context-separation proof…';
    run1.textContent = '…';
    run2.textContent = '…';
    run3.textContent = '…';
    run4.textContent = '…';

    const first = await derivePassword(inputs, silent);
    const second = await derivePassword(inputs, silent);

    const rotated: VaultInputs = { ...inputs, version: inputs.version + 1 };
    label3.textContent = `version ${rotated.version}`;
    const third = await derivePassword(rotated, silent);

    // Change only the context (service/username), keeping the passphrase, to
    // show that context separation holds. Pick a service guaranteed to differ.
    const altService = inputs.service === 'example.org' ? 'example.net' : 'example.org';
    const separated: VaultInputs = { ...inputs, service: altService };
    label4.textContent = `service "${altService}"`;
    const fourth = await derivePassword(separated, silent);

    run1.textContent = first.password;
    run2.textContent = second.password;
    run3.textContent = third.password;
    run4.textContent = fourth.password;

    const deterministic = first.password === second.password;
    const rotates = third.password !== first.password;
    const separates = fourth.password !== first.password;

    if (deterministic && rotates && separates) {
      result.textContent =
        '✅ Determinism holds (Run 1 = Run 2), rotation works (Run 3 differs), and context separation works (Run 4 differs).';
    } else if (!deterministic) {
      result.textContent = '❌ Determinism broken: identical inputs produced different passwords.';
    } else if (!rotates) {
      result.textContent = '❌ Rotation failed: a new version produced the same password.';
    } else {
      result.textContent = '❌ Context separation failed: a different service produced the same password.';
    }
    } finally {
      running = false;
    }
  }

  function reset(): void {
    run1.textContent = '—';
    run2.textContent = '—';
    run3.textContent = '—';
    run4.textContent = '—';
    label3.textContent = 'version + 1';
    label4.textContent = 'different service';
    result.textContent = 'Run proof to compare four derivations.';
  }

  return {
    element: wrapper,
    runProof,
    setBusy,
    reset,
  };
}
