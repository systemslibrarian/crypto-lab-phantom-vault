import { estimateEntropyBits } from '../crypto/charset';

export interface OutputController {
  element: HTMLElement;
  setOutput: (
    password: string,
    charsetSize: number,
    length: number,
    passphraseEntropyBits: number,
  ) => void;
  setStatus: (message: string) => void;
  clear: () => void;
}

function requireNode<T extends Element>(parent: ParentNode, selector: string): T {
  const node = parent.querySelector<T>(selector);
  if (!node) {
    throw new Error(`Missing output node: ${selector}`);
  }
  return node;
}

/**
 * The band an UPPER BOUND puts a passphrase in — and, crucially, whether that
 * bound can carry the band as a verdict.
 *
 * `effectiveBits` is min(format ceiling, composition ceiling), and both terms
 * are ceilings. A ceiling can prove a passphrase is weak; it can never prove one
 * is strong. Printing "Strength: Fair" off it put this page in flat
 * contradiction with its own Break-it panel: measured over the shipped default
 * wordlist, 5 of its 8 entries scored better than Weak — "password123", the
 * phrase behind this page's own "Try a weak passphrase" button, scored 56.9 bits
 * and read "Fair" while the attack below recovers it at guess 5 of 8 (249 ms
 * headless), and "correct horse battery staple" read "Very Strong, about 129
 * bits" while falling at guess 4.
 *
 * So: below the 40-bit line the bound is sound evidence of weakness and the
 * label stands. Above it the label is prefixed as a ceiling, because that is all
 * the number supports.
 */
function strengthLabel(bits: number): { label: string; level: number; sound: boolean } {
  if (bits < 40) {
    // An upper bound under 40 bits PROVES the passphrase is weak. This is the
    // one direction the estimate can carry.
    return { label: 'Weak', level: 25, sound: true };
  }
  if (bits < 70) {
    return { label: 'Fair', level: 50, sound: false };
  }
  if (bits < 100) {
    return { label: 'Strong', level: 75, sound: false };
  }
  return { label: 'Very Strong', level: 100, sound: false };
}

export function createOutput(): OutputController {
  const wrapper = document.createElement('section');
  wrapper.className = 'panel';

  wrapper.innerHTML = `
    <h2 class="panel-title">Password</h2>
    <div class="password-box">
      <input id="password-value" type="password" readonly autocomplete="off" aria-label="Derived password" />
      <button type="button" id="reveal-password" class="small-button">Reveal</button>
      <button type="button" id="copy-password" class="small-button">Copy</button>
    </div>
    <p id="copy-status" class="helper-text" role="status" aria-live="polite"></p>
    <div class="entropy-wrap">
      <p id="strength-label">Strength: n/a</p>
      <div
        class="strength-track"
        role="progressbar"
        aria-valuemin="0"
        aria-valuemax="100"
        aria-valuenow="0"
        aria-label="Estimated password strength"
        id="strength-track"
      >
        <div id="strength-bar" class="strength-bar"></div>
      </div>
      <dl class="entropy-breakdown">
        <div class="entropy-row">
          <dt>Effective entropy</dt>
          <dd id="entropy-effective">n/a</dd>
        </div>
        <div class="entropy-row">
          <dt>Format ceiling</dt>
          <dd id="entropy-ceiling">n/a</dd>
        </div>
        <div class="entropy-row">
          <dt>Master passphrase (upper bound)</dt>
          <dd id="entropy-passphrase">n/a</dd>
        </div>
      </dl>
      <p id="entropy-note" class="helper-text"></p>
    </div>
    <p id="output-live" class="sr-only" aria-live="polite"></p>
  `;

  const passwordInput = requireNode<HTMLInputElement>(wrapper, '#password-value');
  const copyButton = requireNode<HTMLButtonElement>(wrapper, '#copy-password');
  const revealButton = requireNode<HTMLButtonElement>(wrapper, '#reveal-password');
  const copyStatus = requireNode<HTMLElement>(wrapper, '#copy-status');
  const entropyEffective = requireNode<HTMLElement>(wrapper, '#entropy-effective');
  const entropyCeiling = requireNode<HTMLElement>(wrapper, '#entropy-ceiling');
  const entropyPassphrase = requireNode<HTMLElement>(wrapper, '#entropy-passphrase');
  const entropyNote = requireNode<HTMLElement>(wrapper, '#entropy-note');
  const strengthLabelNode = requireNode<HTMLElement>(wrapper, '#strength-label');
  const strengthTrack = requireNode<HTMLElement>(wrapper, '#strength-track');
  const strengthBar = requireNode<HTMLElement>(wrapper, '#strength-bar');
  const liveRegion = requireNode<HTMLElement>(wrapper, '#output-live');

  let clearClipboardTimer: number | null = null;

  revealButton.addEventListener('click', () => {
    const hidden = passwordInput.type === 'password';
    passwordInput.type = hidden ? 'text' : 'password';
    revealButton.textContent = hidden ? 'Hide' : 'Reveal';
  });

  copyButton.addEventListener('click', async () => {
    if (!passwordInput.value) {
      return;
    }

    if (!navigator.clipboard) {
      passwordInput.type = 'text';
      passwordInput.select();
      copyStatus.textContent = 'Clipboard API unavailable. Select password and copy manually.';
      return;
    }

    await navigator.clipboard.writeText(passwordInput.value);
    copyStatus.textContent = 'Copied! Clipboard auto-clear scheduled in 30 s.';

    if (clearClipboardTimer !== null) {
      window.clearTimeout(clearClipboardTimer);
    }

    clearClipboardTimer = window.setTimeout(async () => {
      try {
        await navigator.clipboard.writeText('');
        copyStatus.textContent = 'Clipboard cleared.';
      } catch {
        copyStatus.textContent = 'Clipboard clear failed — clear it manually.';
      }
    }, 30_000);
  });

  function setOutput(
    password: string,
    charsetSize: number,
    length: number,
    passphraseEntropyBits: number,
  ): void {
    passwordInput.value = password;
    passwordInput.type = 'password';
    revealButton.textContent = 'Reveal';

    // The output format can only ever hold this many bits...
    const ceilingBits = estimateEntropyBits(charsetSize, length);
    // ...but a deterministic deriver can never produce MORE entropy than the
    // secret it started from. The weakest link wins.
    const effectiveBits = Math.min(ceilingBits, passphraseEntropyBits);
    const capped = passphraseEntropyBits < ceilingBits;

    const strength = strengthLabel(effectiveBits);

    entropyEffective.textContent = `${effectiveBits.toFixed(1)} bits`;
    entropyCeiling.textContent = `${ceilingBits.toFixed(1)} bits (${length} chars × log₂ ${charsetSize})`;
    entropyPassphrase.textContent = `${passphraseEntropyBits.toFixed(1)} bits`;
    const bothCeilings =
      ' Both numbers above are ceilings: the passphrase figure is length × log₂(apparent character pool), which assumes the phrase was drawn uniformly from that pool. A phrase in an attacker\'s dictionary is worth a handful of bits no matter what it scores here — the Break-it panel below is where that gets tested.';
    entropyNote.textContent =
      (capped
        ? 'Your master passphrase — not the charset — is the limit here. Deterministic derivation cannot add entropy a weak passphrase never had.'
        : 'The output format is the lower of the two ceilings here. That is not a verdict on the passphrase: raising length or enabling more character classes moves this bar, and moves nothing about how guessable the phrase is.') +
      bothCeilings;

    // A ceiling can prove weakness; it cannot certify strength. Only the "Weak"
    // band is stated as a verdict — everything above it is stated as a limit.
    const rendered = strength.sound ? strength.label : `at most ${strength.label}`;
    strengthLabelNode.textContent = `Strength: ${rendered}`;
    strengthBar.style.width = `${strength.level}%`;
    strengthTrack.setAttribute('aria-valuenow', String(strength.level));
    strengthTrack.setAttribute(
      'aria-valuetext',
      strength.sound
        ? `${strength.label}, about ${effectiveBits.toFixed(0)} bits`
        : `at most ${strength.label}, no more than ${effectiveBits.toFixed(0)} bits`,
    );
    liveRegion.textContent = strength.sound
      ? `Password derived. Estimated strength ${strength.label}, about ${effectiveBits.toFixed(0)} bits of effective entropy.`
      : `Password derived. Upper bound only: at most ${strength.label}, no more than ${effectiveBits.toFixed(0)} bits. The real figure depends on how the passphrase was chosen and can be far lower.`;
  }

  function setStatus(message: string): void {
    copyStatus.textContent = message;
  }

  function clear(): void {
    passwordInput.value = '';
    entropyEffective.textContent = 'n/a';
    entropyCeiling.textContent = 'n/a';
    entropyPassphrase.textContent = 'n/a';
    entropyNote.textContent = '';
    strengthLabelNode.textContent = 'Strength: n/a';
    strengthBar.style.width = '0%';
    strengthTrack.setAttribute('aria-valuenow', '0');
    strengthTrack.removeAttribute('aria-valuetext');
  }

  return {
    element: wrapper,
    setOutput,
    setStatus,
    clear,
  };
}
