import './style.css';
import { buildCharset, estimatePassphraseEntropyBits } from './crypto/charset';
import { derivePassword, type PipelineStep } from './derive/pipeline';
import { createForm } from './ui/form';
import { createOutput } from './ui/output';
import { createProof } from './ui/proof';
import { createStateDisplay } from './ui/state-display';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('App root not found.');
}

function requireNode<T extends Element>(parent: ParentNode, selector: string): T {
  const node = parent.querySelector<T>(selector);
  if (!node) {
    throw new Error(`Missing required node: ${selector}`);
  }
  return node;
}

app.innerHTML = `
  <a class="skip-link" href="#main-content">Skip to content</a>
  <div class="shell">
    <header class="app-header">
      <div>
        <h1>◈ PHANTOM VAULT</h1>
        <p>No database. No cloud. Pure math.</p>
      </div>
      <button type="button" class="ghost-button" id="open-modal">How It Works</button>
      <button
        type="button"
        class="theme-toggle"
        id="theme-toggle"
        style="position: absolute; top: 0; right: 0"
        aria-label="Switch to light mode"
      >
        🌙
      </button>
    </header>

    <main id="main-content">
    <section class="panel lede" id="intro-panel">
      <p class="lede-text">
        <strong>A password manager that stores nothing.</strong> Instead of saving your
        passwords in a vault, Phantom Vault <em>re-derives</em> them on demand with
        cryptographic math. The same master passphrase plus a site's details always
        reproduce the exact same strong password — so there is no database to breach,
        sync, or back up.
      </p>
      <div class="pipeline-flow" aria-label="Derivation pipeline: master passphrase, then PBKDF2, then HMAC-DRBG, then rejection sampling, then password">
        <span class="flow-node flow-in">Master passphrase + site + version</span>
        <span class="flow-arrow" aria-hidden="true">→</span>
        <span class="flow-node">PBKDF2 · 600k</span>
        <span class="flow-arrow" aria-hidden="true">→</span>
        <span class="flow-node">HMAC-DRBG</span>
        <span class="flow-arrow" aria-hidden="true">→</span>
        <span class="flow-node">Rejection sampling</span>
        <span class="flow-arrow" aria-hidden="true">→</span>
        <span class="flow-node flow-out">Your password</span>
      </div>
      <p class="lede-hint">
        <strong>Try it:</strong> derive a password, then bump the <strong>Version</strong>
        and derive again. Same inputs reproduce it exactly; a new version rotates it —
        all with nothing stored.
      </p>
    </section>

    <section class="panel" id="progress-panel">
      <div class="panel-title-row">
        <h2 class="panel-title">Pipeline Status</h2>
        <span id="pipeline-status" class="status-pill" data-state="ready" role="status" aria-live="polite">Ready</span>
      </div>
      <div class="progress-track" aria-hidden="true">
        <div id="progress-bar" class="progress-bar"></div>
      </div>
      <p id="progress-text">Idle — enter a master passphrase and select <strong>Derive Password</strong> to start.</p>
      <ul id="step-list" class="step-list" aria-live="polite"></ul>
    </section>

    <div id="mount-form"></div>
    <div id="mount-output"></div>
    <div id="mount-state"></div>
    <div id="mount-proof"></div>
    </main>
<footer style="margin-top:3rem;padding:2rem 1rem;border-top:1px solid rgba(128,128,128,.25);text-align:center;font-size:.85rem;line-height:1.9;opacity:.85;font-family:ui-monospace,Menlo,Consolas,monospace">
  <div><strong>Related demos:</strong> <a href="https://systemslibrarian.github.io/crypto-lab-kdf-arena/" style="color:#35d6bb">kdf-arena</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-bcrypt-forge/" style="color:#35d6bb">bcrypt-forge</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-drbg-arena/" style="color:#35d6bb">drbg-arena</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/" style="color:#35d6bb">corrupted-oracle</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-quantum-vault-kpqc/" style="color:#35d6bb">quantum-vault-kpqc</a></div>
  <div style="margin-top:.5rem"><a href="https://github.com/systemslibrarian/crypto-lab-phantom-vault" style="color:#35d6bb">Source on GitHub</a> &middot; <a href="https://crypto-lab.systemslibrarian.dev/" style="color:#35d6bb">More crypto-lab demos</a></div>
  <div style="margin-top:.75rem;opacity:.75">&ldquo;So whether you eat or drink or whatever you do, do it all for the glory of God.&rdquo; &mdash; 1 Corinthians 10:31</div>
</footer>
  </div>

  <dialog id="how-modal" aria-labelledby="how-modal-title">
    <article>
      <h2 id="how-modal-title">How Phantom Vault Works</h2>
      <ol>
        <li>Traditional password managers store secrets. Storage can be breached.</li>
        <li>Phantom Vault stores nothing. Passwords are derived by math on demand.</li>
        <li>Pipeline: passphrase -> PBKDF2 -> HMAC-DRBG -> rejection sampling -> password.</li>
        <li>PBKDF2 slows brute-force attempts with 600,000 SHA-256 iterations.</li>
        <li>HMAC-DRBG follows NIST SP 800-90A Rev.1 §10.1.2 for auditable determinism.</li>
        <li>Rotate by increasing version while preserving old version reproducibility.</li>
        <li>Effective strength is capped by your master passphrase: derivation cannot manufacture entropy a weak passphrase never had.</li>
        <li>Limitation: if master passphrase is compromised, all derived passwords are exposed.</li>
        <li>Sister project: corrupted-oracle (backdoored DRBG demonstration).</li>
        <li>See crypto-compare CSPRNG category for related analyses.</li>
      </ol>
      <button type="button" class="action-button" id="close-modal">Close</button>
    </article>
  </dialog>
`;

const formMount = requireNode<HTMLDivElement>(app, '#mount-form');
const outputMount = requireNode<HTMLDivElement>(app, '#mount-output');
const stateMount = requireNode<HTMLDivElement>(app, '#mount-state');
const proofMount = requireNode<HTMLDivElement>(app, '#mount-proof');
const progressBar = requireNode<HTMLElement>(app, '#progress-bar');
const progressText = requireNode<HTMLElement>(app, '#progress-text');
const pipelineStatus = requireNode<HTMLElement>(app, '#pipeline-status');
const stepList = requireNode<HTMLElement>(app, '#step-list');
const openModal = requireNode<HTMLButtonElement>(app, '#open-modal');
const closeModal = requireNode<HTMLButtonElement>(app, '#close-modal');
const modal = requireNode<HTMLDialogElement>(app, '#how-modal');
const themeToggle = requireNode<HTMLButtonElement>(app, '#theme-toggle');

const form = createForm();
const output = createOutput();
const stateDisplay = createStateDisplay();
const proof = createProof();

formMount.appendChild(form.element);
outputMount.appendChild(output.element);
stateMount.appendChild(stateDisplay.element);
proofMount.appendChild(proof.element);
setupThemeToggle(themeToggle);

const stepDescriptions: Record<PipelineStep, string> = {
  stretching: 'Passphrase stretched (600,000 PBKDF2-SHA-256 iterations)',
  instantiating: 'HMAC-DRBG instantiated (SP 800-90A Rev.1 §10.1.2.3)',
  generating: 'DRBG bytes generated (SP 800-90A Rev.1 §10.1.2.5)',
  mapping: 'Mapped with rejection sampling (uniform distribution)',
  complete: 'Password derivation complete',
};

const completed = new Set<PipelineStep>();

type Theme = 'dark' | 'light';

function setupThemeToggle(button: HTMLButtonElement): void {
  const root = document.documentElement;

  const getTheme = (): Theme => (root.getAttribute('data-theme') === 'light' ? 'light' : 'dark');

  const renderButtonState = (theme: Theme): void => {
    button.textContent = theme === 'dark' ? '🌙' : '☀️';
    button.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  };

  const applyTheme = (theme: Theme, persist: boolean): void => {
    root.setAttribute('data-theme', theme);
    renderButtonState(theme);
    if (persist) {
      localStorage.setItem('theme', theme);
    }
  };

  const saved = localStorage.getItem('theme');
  const initialTheme: Theme = saved === 'light' || saved === 'dark' ? saved : getTheme();
  applyTheme(initialTheme, false);

  button.addEventListener('click', () => {
    const nextTheme: Theme = getTheme() === 'dark' ? 'light' : 'dark';
    applyTheme(nextTheme, true);
  });
}

type PipelineState = 'ready' | 'running' | 'done' | 'error';

const pipelineStateLabels: Record<PipelineState, string> = {
  ready: 'Ready',
  running: 'Working…',
  done: 'Complete',
  error: 'Error',
};

function setPipelineState(state: PipelineState): void {
  pipelineStatus.dataset.state = state;
  pipelineStatus.textContent = pipelineStateLabels[state];
}

function setProgress(step: PipelineStep, pct: number): void {
  progressBar.style.width = `${pct}%`;
  setPipelineState(step === 'complete' && pct === 100 ? 'done' : 'running');

  if (step === 'stretching') {
    progressText.textContent = `Stretching passphrase... ${pct}% (this takes 1-3 seconds; high iteration count increases brute-force cost)`;
  } else {
    progressText.textContent = stepDescriptions[step];
  }

  if (pct === 100) {
    completed.add(step);
  }

  stepList.innerHTML = '';
  for (const key of ['stretching', 'instantiating', 'generating', 'mapping', 'complete'] as PipelineStep[]) {
    if (!completed.has(key)) {
      continue;
    }
    const item = document.createElement('li');
    item.textContent = `✅ ${stepDescriptions[key]}`;
    stepList.appendChild(item);
  }
}

async function runDerivation(forProof = false): Promise<void> {
  form.setError('');
  form.setWarning('');
  output.setStatus('');
  completed.clear();

  const inputs = form.getInputs();

  if (!inputs.masterPassphrase.trim()) {
    form.setError('Master passphrase cannot be empty.');
    return;
  }

  if (inputs.version < 1) {
    form.setError('Version must be at least 1.');
    return;
  }

  if (inputs.length < 8 || inputs.length > 64) {
    form.setError('Length must be between 8 and 64.');
    return;
  }

  const enabledClasses = [inputs.charset.lowercase, inputs.charset.uppercase, inputs.charset.digits, inputs.charset.symbols].filter(Boolean).length;
  if (enabledClasses === 1) {
    form.setWarning('Only one character class selected — entropy is significantly reduced.');
  } else if (!inputs.service || !inputs.username) {
    form.setWarning('Service or username is blank. This is allowed, but reduces context separation.');
  }

  form.setBusy(true);
  proof.setBusy(true);
  setPipelineState('running');
  progressBar.style.width = '0%';

  try {
    const result = await derivePassword(inputs, setProgress);
    const charset = buildCharset(inputs.charset);
    const passphraseEntropyBits = estimatePassphraseEntropyBits(inputs.masterPassphrase);
    output.setOutput(result.password, charset.length, inputs.length, passphraseEntropyBits);
    stateDisplay.setStates(result.drbgStates, result.bytesGenerated, result.rejectionCount);

    const generateCalls = Math.max(0, result.drbgStates.length - 1);
    output.setStatus(`Generated ${result.bytesGenerated} bytes across ${generateCalls} DRBG generate call(s).`);

    if (result.meta.warning) {
      form.setWarning(result.meta.warning);
    }

    if (forProof) {
      await proof.runProof(inputs);
    }

    form.clearSensitive();
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown derivation error.';
    form.setError(message);
    output.clear();
    setPipelineState('error');
    progressText.textContent = message;
  } finally {
    form.setBusy(false);
    proof.setBusy(false);
  }
}

form.onDerive(() => {
  void runDerivation(false);
});

form.onProof(() => {
  void runDerivation(true);
});

openModal.addEventListener('click', () => {
  modal.showModal();
});

closeModal.addEventListener('click', () => {
  modal.close();
});

window.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && modal.open) {
    modal.close();
  }
});

window.addEventListener('beforeunload', () => {
  form.clearAllInputs();
});
