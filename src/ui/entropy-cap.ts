import { DEFAULT_WORDLIST } from '../attack/cracker';
import { buildCharset, estimateEntropyBits, estimatePassphraseEntropyBits } from '../crypto/charset';
import type { CharsetConfig, VaultInputs } from '../types/vault';
import { PBKDF2_SEED_BITS } from '../crypto/seed-size';

/** Counted from the shipped list, so the copy below cannot drift from it. */
const WORDLIST_SIZE = DEFAULT_WORDLIST.length;

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
      watch the <strong>format ceiling</strong> climb — while the <strong>entropy upper bound</strong>
      cannot exceed either the composition model or the ${PBKDF2_SEED_BITS}-bit seed. That gap is why passphrase choice matters
      more than a long password.
    </p>
    <p class="helper-text">
      <strong>Read both bars as ceilings.</strong> The passphrase figure is
      length × log₂(apparent character pool) — a bound that assumes the phrase was drawn
      uniformly from that pool, which no human-chosen phrase is. It cannot certify strength;
      it can only rule it out. <code>password123</code> scores 57 bits here and the Break-it
      panel below recovers it from a ${WORDLIST_SIZE}-line wordlist.
    </p>

    <div class="cap-chart" role="group" aria-label="Entropy upper bound versus format ceiling, limited by composition and seed width">
      <div class="cap-row">
        <span class="cap-name" id="cap-ceiling-name">Format ceiling</span>
        <div class="cap-track">
          <div class="cap-bar cap-bar-ceiling" id="cap-ceiling-bar"></div>
          <div class="cap-line" id="cap-line" aria-hidden="true"></div>
        </div>
        <span class="cap-value" id="cap-ceiling-value">0 bits</span>
      </div>
      <div class="cap-row">
        <span class="cap-name" id="cap-effective-name">Entropy upper bound</span>
        <div class="cap-track">
          <div class="cap-bar cap-bar-effective" id="cap-effective-bar"></div>
          <div class="cap-line" id="cap-line-2" aria-hidden="true"></div>
        </div>
        <span class="cap-value" id="cap-effective-value">0 bits</span>
      </div>
      <p class="cap-caption" id="cap-caption">
        The dashed line marks the lower composition/seed ceiling; actual entropy is not measured.
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
    const secretCeiling = Math.min(passphraseBits, PBKDF2_SEED_BITS);
    const effectiveBits = Math.min(ceilingBits, secretCeiling);
    const capped = secretCeiling < ceilingBits;
    const seedLimited = PBKDF2_SEED_BITS < Math.min(ceilingBits, passphraseBits);

    ceilingBar.style.width = `${pct(ceilingBits)}%`;
    effectiveBar.style.width = `${pct(effectiveBits)}%`;
    ceilingValue.textContent = `${ceilingBits.toFixed(0)} bits`;
    effectiveValue.textContent = `${effectiveBits.toFixed(0)} bits`;

    const linePct = `${pct(secretCeiling)}%`;
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

    caption.textContent = `Master-passphrase composition ceiling: ${passphraseBits.toFixed(0)} bits; PBKDF2 seed ceiling: ${PBKDF2_SEED_BITS} bits. The dashed line marks the lower ceiling. Actual entropy is not measured: it depends on how the passphrase was chosen and can be far lower.`;
    effectiveBar.dataset.capped = capped ? 'true' : 'false';

    // Both branches used to state the composition bound as a measurement. It is
    // an upper bound, and the "not capped" branch went further and endorsed the
    // passphrase — "not what's holding you back" — which the page's own attack
    // panel can contradict: at length 8 with all four classes that verdict fires
    // for `password123`, the phrase behind the preset button directly above,
    // which the Break-it panel recovers from its ${WORDLIST_SIZE}-line default
    // wordlist. "correct horse battery staple" draws the same endorsement across
    // lengths 8-25 and falls from that same list too.
    verdict.textContent = seedLimited
      ? `Capped by the ${PBKDF2_SEED_BITS}-bit PBKDF2 seed: the format could hold ${ceilingBits.toFixed(0)} bits, but the fixed-context deterministic pipeline has no more than ${PBKDF2_SEED_BITS} bits of reachable-support capacity. This is not a measurement of entropy or a guarantee of uniformity. The passphrase may be much more guessable.`
      : capped
      ? `Capped: the format could hold ${ceilingBits.toFixed(0)} bits, but this passphrase caps effective strength at no more than ${effectiveBits.toFixed(0)}. Cranking length or charset moves only the top bar.`
      : `Not capped by composition or seed: the ${ceilingBits.toFixed(0)}-bit format is the lower ceiling here; composition gives ${passphraseBits.toFixed(0)} bits and the seed gives ${PBKDF2_SEED_BITS} bits. That bound is not a measurement — it assumes the phrase was picked uniformly from its character pool, and says nothing about whether it is in an attacker's dictionary. Try the Break-it panel below before treating it as strength.`;
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
