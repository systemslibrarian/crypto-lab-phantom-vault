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
      <div id="state-list" class="state-list"></div>
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
