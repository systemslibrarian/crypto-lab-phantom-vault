import { buildCharset, estimateEntropyBits, estimatePassphraseEntropyBits } from '../crypto/charset';
import type { CharsetConfig, VaultInputs } from '../types/vault';

export interface EntropyCapController {
  element: HTMLElement;
  /** Recompute both bars from the current form inputs (call on every edit). */
  update: (inputs: Pick<VaultInputs, 'masterPassphrase' | 'length' | 'charset'>) => void;
  /** Register the click handler for the "Try a weak passphrase" preset button. */
  onWeakPreset: (handler: () => void) => void;
}

/** A passphrase that scores low no matter how long you make the password. */
export const WEAK_PRESET = {
  masterPassphrase: 'password123',
  length: 64,
  charset: { lowercase: true, uppercase: true, digits: true, symbols: true } as CharsetConfig,
};

// Shared axis for both bars. Bits above this are still labelled numerically;
// the bar just saturates so the two lengths stay visually comparable.
const AXIS_MAX_BITS = 160;

function requireNode<T extends Element>(parent: ParentNode, selector: string): T {
  const node = parent.querySelector<T>(selector);
  if (!node) {
    throw new Error(`Missing entropy-cap node: ${selector}`);
  }
  return node;
}

function pct(bits: number): number {
  return Math.max(0, Math.min(100, (bits / AXIS_MAX_BITS) * 100));
}

function charsetSize(config: CharsetConfig): number {
  try {
    return buildCharset(config).length;
  } catch {
    return 0;
  }
}

export function createEntropyCap(): EntropyCapController {
  const wrapper = document.createElement('section');
  wrapper.className = 'panel';

  wrapper.innerHTML = `
    <h2 class="panel-title">The entropy cap — the central lesson</h2>
    <p class="helper-text">
      A deterministic deriver can never output more randomness than the master passphrase
      it started from. Drag <strong>Length</strong> and toggle character classes above and
      watch the <strong>format ceiling</strong> climb — while <strong>effective entropy</strong>
      refuses to rise past the passphrase line. That gap is why a strong passphrase matters
      more than a long password.
    </p>

    <div class="cap-chart" role="group" aria-label="Effective entropy versus format ceiling, capped by the master passphrase">
      <div class="cap-row">
        <span class="cap-name" id="cap-ceiling-name">Format ceiling</span>
        <div class="cap-track">
          <div class="cap-bar cap-bar-ceiling" id="cap-ceiling-bar"></div>
          <div class="cap-line" id="cap-line" aria-hidden="true"></div>
        </div>
        <span class="cap-value" id="cap-ceiling-value">0 bits</span>
      </div>
      <div class="cap-row">
        <span class="cap-name" id="cap-effective-name">Effective entropy</span>
        <div class="cap-track">
          <div class="cap-bar cap-bar-effective" id="cap-effective-bar"></div>
          <div class="cap-line" id="cap-line-2" aria-hidden="true"></div>
        </div>
        <span class="cap-value" id="cap-effective-value">0 bits</span>
      </div>
      <p class="cap-caption" id="cap-caption">
        The dashed line marks the master-passphrase entropy — the hard ceiling on effective strength.
      </p>
    </div>

    <div class="cap-actions">
      <button type="button" class="ghost-button" id="cap-weak-preset">
        Try a weak passphrase (password123)
      </button>
    </div>
    <p class="cap-verdict" id="cap-verdict" role="status" aria-live="polite"></p>
  `;

  const ceilingBar = requireNode<HTMLElement>(wrapper, '#cap-ceiling-bar');
  const effectiveBar = requireNode<HTMLElement>(wrapper, '#cap-effective-bar');
  const ceilingValue = requireNode<HTMLElement>(wrapper, '#cap-ceiling-value');
  const effectiveValue = requireNode<HTMLElement>(wrapper, '#cap-effective-value');
  const line1 = requireNode<HTMLElement>(wrapper, '#cap-line');
  const line2 = requireNode<HTMLElement>(wrapper, '#cap-line-2');
  const caption = requireNode<HTMLElement>(wrapper, '#cap-caption');
  const verdict = requireNode<HTMLElement>(wrapper, '#cap-verdict');
  const weakButton = requireNode<HTMLButtonElement>(wrapper, '#cap-weak-preset');

  let presetHandler: (() => void) | null = null;
  weakButton.addEventListener('click', () => presetHandler?.());

  function update(
    inputs: Pick<VaultInputs, 'masterPassphrase' | 'length' | 'charset'>,
  ): void {
    const size = charsetSize(inputs.charset);
    const length = Number.isFinite(inputs.length) ? inputs.length : 0;
    const ceilingBits = estimateEntropyBits(size, length);
    const passphraseBits = estimatePassphraseEntropyBits(inputs.masterPassphrase);
    const effectiveBits = Math.min(ceilingBits, passphraseBits);
    const capped = passphraseBits < ceilingBits;

    ceilingBar.style.width = `${pct(ceilingBits)}%`;
    effectiveBar.style.width = `${pct(effectiveBits)}%`;
    ceilingValue.textContent = `${ceilingBits.toFixed(0)} bits`;
    effectiveValue.textContent = `${effectiveBits.toFixed(0)} bits`;

    const linePct = `${pct(passphraseBits)}%`;
    line1.style.left = linePct;
    line2.style.left = linePct;
    // Hide the marker when the passphrase field is empty (nothing to cap by).
    const hasPassphrase = inputs.masterPassphrase.length > 0;
    line1.style.opacity = hasPassphrase ? '1' : '0';
    line2.style.opacity = hasPassphrase ? '1' : '0';

    if (!hasPassphrase) {
      caption.textContent =
        'Type a master passphrase above — the dashed line will appear where it caps effective strength.';
      verdict.textContent = '';
      effectiveBar.dataset.capped = 'false';
      return;
    }

    caption.textContent = `Master-passphrase entropy (upper bound): ${passphraseBits.toFixed(0)} bits — the dashed line and the hard ceiling on effective strength.`;
    effectiveBar.dataset.capped = capped ? 'true' : 'false';

    verdict.textContent = capped
      ? `Capped: the format could hold ${ceilingBits.toFixed(0)} bits, but this passphrase pins effective strength at ${effectiveBits.toFixed(0)}. Cranking length or charset moves only the top bar.`
      : `Not capped: the ${ceilingBits.toFixed(0)}-bit format is the limit here. This passphrase (${passphraseBits.toFixed(0)} bits upper bound) is not what's holding you back — raise length or add character classes to gain more.`;
  }

  function onWeakPreset(handler: () => void): void {
    presetHandler = handler;
  }

  return {
    element: wrapper,
    update,
    onWeakPreset,
  };
}
