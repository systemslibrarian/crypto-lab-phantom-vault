import type { CharsetConfig, VaultInputs } from '../types/vault';

export interface FormController {
  element: HTMLElement;
  getInputs: () => VaultInputs;
  setBusy: (busy: boolean) => void;
  clearSensitive: () => void;
  clearAllInputs: () => void;
  setError: (message: string) => void;
  setWarning: (message: string) => void;
  onDerive: (handler: () => void) => void;
  onProof: (handler: () => void) => void;
  /** Fires whenever any input the entropy readout depends on changes. */
  onInputChange: (handler: () => void) => void;
  /**
   * Fires only on a USER edit of a derivation input (any of the six fields).
   * Distinct from onInputChange: clearSensitive() — the programmatic wipe after
   * every successful derivation — notifies input listeners but is NOT an edit,
   * so results retired on this hook survive their own derivation's cleanup.
   */
  onEdit: (handler: () => void) => void;
  /**
   * Overwrites passphrase + length + every charset toggle in one shot (used by
   * the "Try a weak passphrase" teaching preset). Fires onInputChange listeners.
   */
  applyPreset: (preset: {
    masterPassphrase: string;
    length: number;
    charset: CharsetConfig;
  }) => void;
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

  wrapper.innerHTML = `
    <h2 class="panel-title">Derive Password</h2>
    <div class="field-grid">
      <label class="field">
        <span>Master Passphrase</span>
        <div class="passphrase-wrap">
          <input type="password" id="master-passphrase" autocomplete="off" required aria-required="true" minlength="1" />
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
      <label><input type="checkbox" id="charset-lower" checked aria-label="Lowercase letters" /> a-z</label>
      <label><input type="checkbox" id="charset-upper" checked aria-label="Uppercase letters" /> A-Z</label>
      <label><input type="checkbox" id="charset-digits" checked aria-label="Digits" /> 0-9</label>
      <label><input type="checkbox" id="charset-symbols" checked aria-label="Symbols" /> !@#</label>
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

  const inputChangeHandlers: Array<() => void> = [];
  const emitInputChange = (): void => {
    for (const handler of inputChangeHandlers) {
      handler();
    }
  };
  const editHandlers: Array<() => void> = [];
  const emitEdit = (): void => {
    for (const handler of editHandlers) {
      handler();
    }
  };

  // Re-apply the "last class can't be unchecked" disabled state. `busy` (below)
  // overrides everything while a derivation is running.
  let busy = false;
  const syncCheckboxLock = (): void => {
    const enabled = checkboxes.filter((entry) => entry.checked).length;
    for (const item of checkboxes) {
      item.disabled = busy || (item.checked && enabled === 1);
    }
  };

  for (const checkbox of checkboxes) {
    checkbox.addEventListener('change', () => {
      const enabledCount = checkboxes.filter((entry) => entry.checked).length;
      if (enabledCount === 0) {
        checkbox.checked = true;
      }

      syncCheckboxLock();
      emitInputChange();
      emitEdit();
    });
  }

  // The entropy-cap exhibit updates live as the learner drags length or types a
  // passphrase, so surface those edits too (not just charset toggles).
  passphraseInput.addEventListener('input', () => {
    emitInputChange();
    emitEdit();
  });
  lengthInput.addEventListener('input', () => {
    emitInputChange();
    emitEdit();
  });
  // These three do not feed the entropy readout, but they are derivation
  // context all the same — editing any of them makes every on-screen result a
  // claim about inputs the page no longer holds.
  serviceInput.addEventListener('input', emitEdit);
  usernameInput.addEventListener('input', emitEdit);
  versionInput.addEventListener('input', emitEdit);

  toggleButton.addEventListener('click', () => {
    const hidden = passphraseInput.type === 'password';
    passphraseInput.type = hidden ? 'text' : 'password';
    toggleButton.textContent = hidden ? 'Hide' : 'Show';
  });

  function setBusy(next: boolean): void {
    busy = next;
    deriveButton.disabled = next;
    proofButton.disabled = next;
    deriveButton.textContent = next ? 'Deriving...' : 'Derive Password';
    // Freeze every derivation input while the pipeline runs. The run derives
    // from a snapshot taken at click time, so a field edited mid-run would get
    // a result computed from values the form no longer shows — the input is
    // disabled rather than silently ignored.
    passphraseInput.disabled = next;
    serviceInput.disabled = next;
    usernameInput.disabled = next;
    versionInput.disabled = next;
    lengthInput.disabled = next;
    syncCheckboxLock();
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
    // Programmatic assignment fires no `input` event, so anything driven by
    // onInputChange never learned the field had been emptied. main.ts calls this
    // at the end of EVERY successful derivation, which left the entropy-cap
    // panel showing the cleared passphrase's dashed line, its bit count and its
    // "Capped: … this passphrase caps effective strength at N" verdict beside a
    // blank field — a claim about a passphrase the page no longer holds, on
    // 100% of derivations.
    emitInputChange();
  }

  function clearAllInputs(): void {
    passphraseInput.value = '';
    serviceInput.value = '';
    usernameInput.value = '';
    versionInput.value = '1';
    lengthInput.value = '20';
    charsetInputs.lower.checked = true;
    charsetInputs.upper.checked = true;
    charsetInputs.digits.checked = true;
    charsetInputs.symbols.checked = true;

    for (const item of checkboxes) {
      item.disabled = false;
    }
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

  function onInputChange(handler: () => void): void {
    inputChangeHandlers.push(handler);
  }

  function onEdit(handler: () => void): void {
    editHandlers.push(handler);
  }

  function applyPreset(preset: {
    masterPassphrase: string;
    length: number;
    charset: CharsetConfig;
  }): void {
    passphraseInput.value = preset.masterPassphrase;
    lengthInput.value = String(preset.length);
    charsetInputs.lower.checked = preset.charset.lowercase;
    charsetInputs.upper.checked = preset.charset.uppercase;
    charsetInputs.digits.checked = preset.charset.digits;
    charsetInputs.symbols.checked = preset.charset.symbols;

    syncCheckboxLock();
    emitInputChange();
    // The preset button is a user edit of the derivation inputs, so it retires
    // results the same way typing into the fields does.
    emitEdit();
  }

  return {
    element: wrapper,
    getInputs,
    setBusy,
    clearSensitive,
    clearAllInputs,
    setError,
    setWarning,
    onDerive,
    onProof,
    onInputChange,
    onEdit,
    applyPreset,
  };
}
