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
  /** Retire the snapshots — they describe a run whose inputs are gone. */
  clear: () => void;
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
        <strong>K</strong> and <strong>V</strong> are the generator's evolving internal memory:
        <strong>K</strong> is the current HMAC key, <strong>V</strong> the running value it hashes.
        Each <code>Generate</code> call feeds them through HMAC to produce a fresh
        <strong>K</strong>,<strong>V</strong> (per NIST SP 800-90A Rev.1) — old state is never
        reused, so the byte stream is reproducible yet non-repeating. Watch them step forward:
      </p>
      <div id="ratchet" class="ratchet" aria-hidden="true"></div>
      <p class="helper-text ratchet-caption" id="ratchet-caption"></p>
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
  const ratchet: HTMLElement = requireNode<HTMLElement>(wrapper, '#ratchet');
  const ratchetCaption: HTMLElement = requireNode<HTMLElement>(wrapper, '#ratchet-caption');

  function shortHex(value: string): string {
    return value.length <= 12 ? value : `${value.slice(0, 6)}…${value.slice(-4)}`;
  }

  // Show the last transition K,V(before) --HMAC--> K,V(after) so "same seed
  // walks the same path" is visible rather than asserted. Uses two real
  // consecutive snapshots from this run; no values are invented.
  function renderRatchet(states: DRBGState[]): void {
    ratchet.innerHTML = '';
    if (states.length < 2) {
      ratchetCaption.textContent = '';
      return;
    }
    const before = states[states.length - 2];
    const after = states[states.length - 1];

    ratchet.innerHTML = `
      <div class="ratchet-node ratchet-before">
        <span class="ratchet-tag">before</span>
        <span class="ratchet-kv"><strong>K</strong> ${shortHex(before.K)}</span>
        <span class="ratchet-kv"><strong>V</strong> ${shortHex(before.V)}</span>
      </div>
      <div class="ratchet-op" aria-hidden="true">
        <span class="ratchet-arrow">→</span>
        <span class="ratchet-hmac">HMAC</span>
        <span class="ratchet-arrow">→</span>
      </div>
      <div class="ratchet-node ratchet-after">
        <span class="ratchet-tag">after</span>
        <span class="ratchet-kv"><strong>K</strong> ${shortHex(after.K)}</span>
        <span class="ratchet-kv"><strong>V</strong> ${shortHex(after.V)}</span>
      </div>
    `;
    // Restart the flow animation on each derive by re-adding the class.
    ratchet.classList.remove('ratchet-run');
    void ratchet.offsetWidth;
    ratchet.classList.add('ratchet-run');
    ratchetCaption.textContent =
      'Same seed always walks the same path: identical inputs reproduce this exact K,V sequence every time.';
  }

  function setStates(states: DRBGState[], generatedBytes: number, rejected: number): void {
    renderRatchet(states);
    list.innerHTML = '';

    for (const [index, state] of states.entries()) {
      const item = document.createElement('article');
      item.className = 'state-item';
      const label = SECTION_LABELS[index] ?? `Generate call ${index}`;
      // Truncated fingerprints only — the full K and V used to ride along in
      // `title` attributes. These values are derived from the master secret
      // (the byte stream that becomes the password is HMAC'd out of them), so
      // the complete state has no business in the DOM; the truncation shows
      // the ratchet stepping without exposing generator state a real password
      // tool must never reveal.
      item.innerHTML = `
        <h3>Step ${index + 1} - ${label}</h3>
        <p><strong>K:</strong> ${truncateHex(state.K)}</p>
        <p><strong>V:</strong> ${truncateHex(state.V)}</p>
        <p><strong>reseedCounter:</strong> ${state.reseedCounter}</p>
      `;
      list.appendChild(item);
    }

    const summary = document.createElement('p');
    summary.className = 'state-summary';
    summary.textContent = `${generatedBytes} bytes generated, ${rejected} rejected by uniform mapping.`;
    list.appendChild(summary);
  }

  function clear(): void {
    ratchet.innerHTML = '';
    ratchetCaption.textContent = '';
    list.innerHTML = '';
  }

  return {
    element: wrapper,
    setStates,
    clear,
  };
}
