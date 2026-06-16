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

function strengthLabel(bits: number): { label: string; level: number } {
  if (bits < 40) {
    return { label: 'Weak', level: 25 };
  }
  if (bits < 70) {
    return { label: 'Fair', level: 50 };
  }
  if (bits < 100) {
    return { label: 'Strong', level: 75 };
  }
  return { label: 'Very Strong', level: 100 };
}

export function createOutput(): OutputController {
  const wrapper = document.createElement('section');
  wrapper.className = 'panel';

  wrapper.innerHTML = `
    <h2 class="panel-title">Password</h2>
    <div class="password-box">
      <input id="password-value" type="password" readonly autocomplete="off" />
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
    entropyNote.textContent = capped
      ? 'Your master passphrase — not the charset — is the limit here. Deterministic derivation cannot add entropy a weak passphrase never had. (Upper bound assumes a random passphrase; a real word or phrase is weaker still.)'
      : 'The output format is the limiting factor. Increase length or enable more character classes to raise the ceiling.';

    strengthLabelNode.textContent = `Strength: ${strength.label}`;
    strengthBar.style.width = `${strength.level}%`;
    strengthTrack.setAttribute('aria-valuenow', String(strength.level));
    strengthTrack.setAttribute('aria-valuetext', `${strength.label}, about ${effectiveBits.toFixed(0)} bits`);
    liveRegion.textContent = `Password derived. Estimated strength ${strength.label}, about ${effectiveBits.toFixed(0)} bits of effective entropy.`;
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
