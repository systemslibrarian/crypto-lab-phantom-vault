import { estimateEntropyBits } from '../crypto/charset';

export interface OutputController {
  element: HTMLElement;
  setOutput: (password: string, charsetSize: number, length: number) => void;
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
      <p id="entropy-label">Entropy: n/a</p>
      <div class="strength-track" aria-hidden="true">
        <div id="strength-bar" class="strength-bar"></div>
      </div>
      <p id="strength-label">Strength: n/a</p>
    </div>
    <p id="output-live" class="sr-only" aria-live="polite"></p>
  `;

  const passwordInput = requireNode<HTMLInputElement>(wrapper, '#password-value');
  const copyButton = requireNode<HTMLButtonElement>(wrapper, '#copy-password');
  const revealButton = requireNode<HTMLButtonElement>(wrapper, '#reveal-password');
  const copyStatus = requireNode<HTMLElement>(wrapper, '#copy-status');
  const entropyLabel = requireNode<HTMLElement>(wrapper, '#entropy-label');
  const strengthLabelNode = requireNode<HTMLElement>(wrapper, '#strength-label');
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
    copyStatus.textContent = 'Copied! Clipboard clears in 30 seconds.';

    if (clearClipboardTimer !== null) {
      window.clearTimeout(clearClipboardTimer);
    }

    clearClipboardTimer = window.setTimeout(async () => {
      try {
        await navigator.clipboard.writeText('');
      } catch {
        // Browser permissions can prevent clipboard clearing.
      }
      copyStatus.textContent = '';
    }, 30_000);
  });

  function setOutput(password: string, charsetSize: number, length: number): void {
    passwordInput.value = password;
    passwordInput.type = 'password';
    revealButton.textContent = 'Reveal';

    const bits = estimateEntropyBits(charsetSize, length);
    const strength = strengthLabel(bits);

    entropyLabel.textContent = `Entropy: ${bits.toFixed(1)} bits`;
    strengthLabelNode.textContent = `Strength: ${strength.label}`;
    strengthBar.style.width = `${strength.level}%`;
    liveRegion.textContent = 'Password derived';
  }

  function setStatus(message: string): void {
    copyStatus.textContent = message;
  }

  function clear(): void {
    passwordInput.value = '';
    entropyLabel.textContent = 'Entropy: n/a';
    strengthLabelNode.textContent = 'Strength: n/a';
    strengthBar.style.width = '0%';
  }

  return {
    element: wrapper,
    setOutput,
    setStatus,
    clear,
  };
}
