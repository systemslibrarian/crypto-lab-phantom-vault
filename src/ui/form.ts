import type { CharsetConfig, VaultInputs } from '../types/vault';

export interface FormController {
  element: HTMLElement;
  getInputs: () => VaultInputs;
  setBusy: (busy: boolean) => void;
  clearSensitive: () => void;
  setError: (message: string) => void;
  setWarning: (message: string) => void;
  onDerive: (handler: () => void) => void;
  onProof: (handler: () => void) => void;
}

function requireNode<T extends Element>(parent: ParentNode, selector: string): T {
  const node = parent.querySelector<T>(selector);
  if (!node) {
    throw new Error(`Missing form node: ${selector}`);
  }
  return node;
}

function buildInitialCharset(): CharsetConfig {
  return {
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
  };
}

export function createForm(): FormController {
  const wrapper = document.createElement('section');
  wrapper.className = 'panel panel-form';
  wrapper.id = 'main-content';
  wrapper.tabIndex = -1;

  wrapper.innerHTML = `
    <h2 class="panel-title">Derive Password</h2>
    <div class="field-grid">
      <label class="field">
        <span>Master Passphrase</span>
        <div class="passphrase-wrap">
          <input type="password" id="master-passphrase" autocomplete="off" required minlength="1" />
          <button type="button" class="small-button" id="toggle-passphrase" aria-label="Toggle passphrase visibility">Show</button>
        </div>
      </label>
      <label class="field">
        <span>Service</span>
        <input type="text" id="service" autocomplete="off" spellcheck="false" placeholder="github.com" />
      </label>
      <label class="field">
        <span>Username</span>
        <input type="text" id="username" autocomplete="off" placeholder="name@example.com" />
      </label>
      <div class="field-inline-row">
        <label class="field field-inline">
          <span>Version</span>
          <input type="number" id="version" min="1" max="999" value="1" />
        </label>
        <label class="field field-inline">
          <span>Length</span>
          <input type="number" id="length" min="8" max="64" value="20" />
        </label>
      </div>
    </div>

    <fieldset class="charset-fieldset">
      <legend>Character Set</legend>
      <label><input type="checkbox" id="charset-lower" checked /> a-z</label>
      <label><input type="checkbox" id="charset-upper" checked /> A-Z</label>
      <label><input type="checkbox" id="charset-digits" checked /> 0-9</label>
      <label><input type="checkbox" id="charset-symbols" checked /> !@#</label>
    </fieldset>

    <p class="helper-text" id="form-warning" role="status" aria-live="polite"></p>
    <p class="error-text" id="form-error" role="alert"></p>

    <div class="form-actions">
      <button type="button" id="derive-button" class="action-button">Derive Password</button>
      <button type="button" id="proof-button" class="ghost-button">Run Proof</button>
    </div>
  `;

  const passphraseInput = requireNode<HTMLInputElement>(wrapper, '#master-passphrase');
  const serviceInput = requireNode<HTMLInputElement>(wrapper, '#service');
  const usernameInput = requireNode<HTMLInputElement>(wrapper, '#username');
  const versionInput = requireNode<HTMLInputElement>(wrapper, '#version');
  const lengthInput = requireNode<HTMLInputElement>(wrapper, '#length');
  const deriveButton = requireNode<HTMLButtonElement>(wrapper, '#derive-button');
  const proofButton = requireNode<HTMLButtonElement>(wrapper, '#proof-button');
  const toggleButton = requireNode<HTMLButtonElement>(wrapper, '#toggle-passphrase');
  const warningNode = requireNode<HTMLElement>(wrapper, '#form-warning');
  const errorNode = requireNode<HTMLElement>(wrapper, '#form-error');

  const charsetInputs = {
    lower: requireNode<HTMLInputElement>(wrapper, '#charset-lower'),
    upper: requireNode<HTMLInputElement>(wrapper, '#charset-upper'),
    digits: requireNode<HTMLInputElement>(wrapper, '#charset-digits'),
    symbols: requireNode<HTMLInputElement>(wrapper, '#charset-symbols'),
  };

  const checkboxes = [
    charsetInputs.lower,
    charsetInputs.upper,
    charsetInputs.digits,
    charsetInputs.symbols,
  ];

  for (const checkbox of checkboxes) {
    checkbox.addEventListener('change', () => {
      const enabledCount = checkboxes.filter((entry) => entry.checked).length;
      if (enabledCount === 0) {
        checkbox.checked = true;
      }

      for (const item of checkboxes) {
        item.disabled = item.checked && checkboxes.filter((entry) => entry.checked).length === 1;
      }
    });
  }

  toggleButton.addEventListener('click', () => {
    const hidden = passphraseInput.type === 'password';
    passphraseInput.type = hidden ? 'text' : 'password';
    toggleButton.textContent = hidden ? 'Hide' : 'Show';
  });

  function setBusy(busy: boolean): void {
    deriveButton.disabled = busy;
    proofButton.disabled = busy;
    deriveButton.textContent = busy ? 'Deriving...' : 'Derive Password';
  }

  function getInputs(): VaultInputs {
    const config = buildInitialCharset();
    config.lowercase = charsetInputs.lower.checked;
    config.uppercase = charsetInputs.upper.checked;
    config.digits = charsetInputs.digits.checked;
    config.symbols = charsetInputs.symbols.checked;

    return {
      masterPassphrase: passphraseInput.value,
      service: serviceInput.value.trim(),
      username: usernameInput.value.trim(),
      version: Number(versionInput.value),
      length: Number(lengthInput.value),
      charset: config,
    };
  }

  function clearSensitive(): void {
    passphraseInput.value = '';
  }

  function setError(message: string): void {
    errorNode.textContent = message;
  }

  function setWarning(message: string): void {
    warningNode.textContent = message;
  }

  function onDerive(handler: () => void): void {
    deriveButton.addEventListener('click', handler);
  }

  function onProof(handler: () => void): void {
    proofButton.addEventListener('click', handler);
  }

  return {
    element: wrapper,
    getInputs,
    setBusy,
    clearSensitive,
    setError,
    setWarning,
    onDerive,
    onProof,
  };
}
