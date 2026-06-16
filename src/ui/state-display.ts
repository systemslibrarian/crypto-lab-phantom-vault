import type { DRBGState } from '../types/vault';

const SECTION_LABELS = [
  'Instantiate (SP 800-90A Rev.1 §10.1.2.3)',
  'Generate (SP 800-90A Rev.1 §10.1.2.5)',
];

function truncateHex(value: string): string {
  if (value.length <= 32) {
    return value;
  }
  return `${value.slice(0, 16)}...${value.slice(-8)}`;
}

export interface StateDisplay {
  element: HTMLElement;
  setStates: (states: DRBGState[], generatedBytes: number, rejected: number) => void;
}

function requireNode<T extends Element>(parent: ParentNode, selector: string): T {
  const node = parent.querySelector<T>(selector);
  if (!node) {
    throw new Error(`Missing state display node: ${selector}`);
  }
  return node;
}

export function createStateDisplay(): StateDisplay {
  const wrapper = document.createElement('section');
  wrapper.className = 'panel';

  wrapper.innerHTML = `
    <details>
      <summary>HMAC-DRBG State Machine</summary>
      <p class="helper-text state-intro">
        Each <code>Generate</code> call ratchets the internal state forward: a fresh key
        <strong>K</strong> and value <strong>V</strong> per NIST SP 800-90A Rev.1. The state is
        never reused, so the byte stream is reproducible yet non-repeating.
      </p>
      <div id="state-list" class="state-list"></div>
      <details class="rejection-note">
        <summary>Why are bytes rejected?</summary>
        <p class="helper-text">
          To pick a character uniformly from a set of <em>N</em>, we cannot just take
          <code>byte % N</code>: 256 is rarely a multiple of <em>N</em>, so the low values would
          appear slightly more often — <strong>modulo bias</strong>. Instead we reject any byte at or
          above <code>floor(256 / N) × N</code> and draw again. Every accepted byte then maps to an
          exactly uniform character. The count below is how many bytes were discarded to keep the
          distribution flat. (<code>npm run verify:uniformity</code> checks this with a chi-square test.)
        </p>
      </details>
    </details>
  `;

  const list: HTMLElement = requireNode<HTMLElement>(wrapper, '#state-list');

  function setStates(states: DRBGState[], generatedBytes: number, rejected: number): void {
    list.innerHTML = '';

    for (const [index, state] of states.entries()) {
      const item = document.createElement('article');
      item.className = 'state-item';
      const label = SECTION_LABELS[index] ?? `Generate call ${index}`;
      item.innerHTML = `
        <h3>Step ${index + 1} - ${label}</h3>
        <p title="${state.K}"><strong>K:</strong> ${truncateHex(state.K)}</p>
        <p title="${state.V}"><strong>V:</strong> ${truncateHex(state.V)}</p>
        <p><strong>reseedCounter:</strong> ${state.reseedCounter}</p>
      `;
      list.appendChild(item);
    }

    const summary = document.createElement('p');
    summary.className = 'state-summary';
    summary.textContent = `${generatedBytes} bytes generated, ${rejected} rejected by uniform mapping.`;
    list.appendChild(summary);
  }

  return {
    element: wrapper,
    setStates,
  };
}
