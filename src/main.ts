import './style.css';
import { buildCharset, estimatePassphraseEntropyBits } from './crypto/charset';
import { derivePassword, type PipelineStep } from './derive/pipeline';
import { createForm } from './ui/form';
import { createOutput } from './ui/output';
import { createProof } from './ui/proof';
import { createStateDisplay } from './ui/state-display';
import { createEntropyCap, WEAK_PRESET } from './ui/entropy-cap';
import { createDistribution } from './ui/distribution';
import { createCracker } from './ui/cracker';

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
  <div class="shell">
    <main id="main-content">
    <header class="cl-hero">
      <div class="cl-hero-main">
        <h1 class="cl-hero-title">Phantom Vault</h1>
        <p class="cl-hero-sub">Stateless password derivation · PBKDF2 → HMAC-DRBG → rejection sampling</p>
        <p class="cl-hero-desc">
          Regenerate a site-specific password on demand from a master passphrase plus
          context, watching PBKDF2 key-stretch, HMAC-DRBG, and rejection sampling build
          it step by step — with nothing stored.
        </p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">
          A vault you never store is a vault no one can breach or sync. Bump the version to
          rotate a leaked password, and context keeps each site independent — but effective
          strength is capped by your master passphrase.
        </p>
      </aside>
    </header>

    <div class="header-actions">
      <button type="button" class="ghost-button" id="open-modal">How It Works</button>
      <button
        type="button"
        class="theme-toggle"
        id="theme-toggle"
        hidden
        aria-hidden="true"
        aria-label="Switch to light mode"
      >
        🌙
      </button>
    </div>

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

    <section class="panel" id="how-to-panel">
      <h2 class="panel-title">How to use</h2>
      <ol class="how-steps">
        <li><span class="num">1</span><span>Type a <strong>master passphrase</strong> you can remember — it's the only secret.</span></li>
        <li><span class="num">2</span><span>Enter the <strong>service</strong> and <strong>username</strong> (e.g. github.com, you@example.com).</span></li>
        <li><span class="num">3</span><span>Click <strong>Derive Password</strong>. The pipeline below runs and your password appears — nothing is stored.</span></li>
      </ol>
    </section>

    <section class="panel" id="progress-panel">
      <div class="panel-title-row">
        <h2 class="panel-title">Pipeline Status</h2>
        <span id="pipeline-status" class="status-pill" data-state="ready" role="status" aria-live="polite">Ready</span>
      </div>
      <p class="helper-text" id="pipeline-intro">These five steps run every time you derive. They stay visible so you can follow exactly what happens to your passphrase.</p>
      <div class="progress-track" aria-hidden="true">
        <div id="progress-bar" class="progress-bar"></div>
      </div>
      <p id="progress-text">Idle — enter a master passphrase and select <strong>Derive Password</strong> to start.</p>
      <ul id="step-list" class="step-list"></ul>
    </section>

    <div id="mount-form"></div>
    <div id="mount-output"></div>
    <div id="mount-entropy-cap"></div>
    <div id="mount-cracker"></div>
    <div id="mount-state"></div>
    <div id="mount-distribution"></div>
    <div id="mount-proof"></div>
    </main>
<!-- The muted footer look comes from color tokens, not a container opacity:
     an opacity group fades the links with everything else, and at .85 the
     accent links measured 4.30:1 (dark) / 3.75:1 (light) — under WCAG 1.4.3's
     4.5:1 — while reading as passing values in the stylesheet. -->
<footer style="margin-top:3rem;padding:2rem 1rem;border-top:1px solid rgba(128,128,128,.25);text-align:center;font-size:.85rem;line-height:1.9;color:var(--muted);font-family:ui-monospace,Menlo,Consolas,monospace">
  <div><strong>Related demos:</strong> <a href="https://systemslibrarian.github.io/crypto-lab-kdf-arena/" style="color:var(--accent)">kdf-arena</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-bcrypt-forge/" style="color:var(--accent)">bcrypt-forge</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-drbg-arena/" style="color:var(--accent)">drbg-arena</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/" style="color:var(--accent)">corrupted-oracle</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-quantum-vault-kpqc/" style="color:var(--accent)">quantum-vault-kpqc</a></div>
  <div style="margin-top:.5rem"><a href="https://github.com/systemslibrarian/crypto-lab-phantom-vault" style="color:var(--accent)">Source on GitHub</a> &middot; <a href="https://crypto-lab.systemslibrarian.dev/" style="color:var(--accent)">More crypto-lab demos</a></div>
  <div style="margin-top:.75rem">&ldquo;So whether you eat or drink or whatever you do, do it all for the glory of God.&rdquo; &mdash; 1 Corinthians 10:31</div>
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
const entropyCapMount = requireNode<HTMLDivElement>(app, '#mount-entropy-cap');
const stateMount = requireNode<HTMLDivElement>(app, '#mount-state');
const crackerMount = requireNode<HTMLDivElement>(app, '#mount-cracker');
const distributionMount = requireNode<HTMLDivElement>(app, '#mount-distribution');
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
const entropyCap = createEntropyCap();
const stateDisplay = createStateDisplay();
const distribution = createDistribution();
const cracker = createCracker();
const proof = createProof();

formMount.appendChild(form.element);
outputMount.appendChild(output.element);
entropyCapMount.appendChild(entropyCap.element);
stateMount.appendChild(stateDisplay.element);
crackerMount.appendChild(cracker.element);
distributionMount.appendChild(distribution.element);
proofMount.appendChild(proof.element);
setupThemeToggle(themeToggle);

// Live entropy-cap exhibit: recompute the two bars from the current form inputs
// on every edit, so the learner watches the ceiling climb while effective
// entropy stays pinned by the passphrase — without needing to derive.
function refreshEntropyCap(): void {
  const inputs = form.getInputs();
  entropyCap.update({
    masterPassphrase: inputs.masterPassphrase,
    length: inputs.length,
    charset: inputs.charset,
  });
}
form.onInputChange(refreshEntropyCap);
entropyCap.onWeakPreset(() => {
  form.applyPreset(WEAK_PRESET);
});
refreshEntropyCap();

interface StepInfo {
  key: PipelineStep;
  label: string;
  plain: string;
}

// Ordered pipeline steps. `label` is the technical name (with the relevant
// standard reference); `plain` is a one-line, jargon-free explanation of what
// the step actually does. Both render together so the steps are legible to
// newcomers and precise for those who want the spec.
const STEPS: StepInfo[] = [
  {
    key: 'stretching',
    label: 'PBKDF2 key stretch (600,000 SHA-256 iterations)',
    plain: 'Hashes your passphrase 600,000 times so each guess an attacker makes is slow and costly.',
  },
  {
    key: 'instantiating',
    label: 'HMAC-DRBG instantiate (SP 800-90A Rev.1 §10.1.2.3)',
    plain: 'Seeds a deterministic random-byte generator from that hash.',
  },
  {
    key: 'generating',
    label: 'Generate DRBG bytes (SP 800-90A Rev.1 §10.1.2.5)',
    plain: 'Produces a reproducible stream of unpredictable-looking bytes.',
  },
  {
    key: 'mapping',
    label: 'Rejection sampling',
    plain: 'Maps those bytes onto your character set evenly, with no bias toward any character.',
  },
  {
    key: 'complete',
    label: 'Password ready',
    plain: 'Same inputs always rebuild the same password — so nothing ever needs to be stored.',
  },
];

const stepByKey = new Map<PipelineStep, StepInfo>(STEPS.map((step) => [step.key, step]));

const completed = new Set<PipelineStep>();
let activeStep: PipelineStep | null = null;

// Paint the full pipeline checklist (all steps pending) as soon as the page
// loads so visitors can see the steps before deriving anything.
renderSteps();

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

function renderSteps(): void {
  stepList.innerHTML = '';
  for (const info of STEPS) {
    const state = completed.has(info.key) ? 'done' : info.key === activeStep ? 'active' : 'pending';
    const icon = state === 'done' ? '✅' : state === 'active' ? '⏳' : '○';

    const item = document.createElement('li');
    item.className = 'step-item';
    item.dataset.state = state;

    const iconNode = document.createElement('span');
    iconNode.className = 'step-icon';
    iconNode.setAttribute('aria-hidden', 'true');
    iconNode.textContent = icon;

    const body = document.createElement('span');
    body.className = 'step-body';

    const label = document.createElement('span');
    label.className = 'step-label';
    label.textContent = info.label;

    const plain = document.createElement('span');
    plain.className = 'step-plain';
    plain.textContent = info.plain;

    body.append(label, plain);
    item.append(iconNode, body);
    stepList.appendChild(item);
  }
}

function resetProgress(): void {
  completed.clear();
  activeStep = null;
  progressBar.style.width = '0%';
  progressText.textContent = 'Idle — enter a master passphrase and select Derive Password to start.';
  setPipelineState('ready');
  renderSteps();
}

function setProgress(step: PipelineStep, pct: number): void {
  progressBar.style.width = `${pct}%`;
  activeStep = step;
  setPipelineState(step === 'complete' && pct === 100 ? 'done' : 'running');

  if (pct === 100) {
    completed.add(step);
  }

  if (step === 'stretching' && pct < 100) {
    progressText.textContent = `Stretching passphrase... ${pct}% (this takes 1-3 seconds; high iteration count increases brute-force cost)`;
  } else {
    progressText.textContent = stepByKey.get(step)?.label ?? 'Working...';
  }

  renderSteps();
}

async function runDerivation(forProof = false): Promise<void> {
  form.setError('');
  form.setWarning('');
  output.setStatus('');
  resetProgress();

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
  cracker.setBusy(true);
  setPipelineState('running');
  progressBar.style.width = '0%';

  try {
    const result = await derivePassword(inputs, setProgress);
    const charset = buildCharset(inputs.charset);
    const passphraseEntropyBits = estimatePassphraseEntropyBits(inputs.masterPassphrase);
    output.setOutput(result.password, charset.length, inputs.length, passphraseEntropyBits);
    stateDisplay.setStates(result.drbgStates, result.bytesGenerated, result.rejectionCount);
    distribution.render(result.sampledBytes, charset.length);
    // Hand the attack panel exactly what an attacker would hold after this
    // derivation: the derived password and the public context, never the
    // passphrase (which form.clearSensitive() wipes a few lines below).
    cracker.arm({
      password: result.password,
      service: inputs.service,
      username: inputs.username,
      version: inputs.version,
      length: inputs.length,
      charset: inputs.charset,
    });

    const generateCalls = Math.max(0, result.drbgStates.length - 1);
    output.setStatus(`Generated ${result.bytesGenerated} bytes across ${generateCalls} DRBG generate call(s).`);

    if (result.meta.warning) {
      form.setWarning(result.meta.warning);
    }

    if (forProof) {
      await proof.runProof(inputs);
    }

    hasResults = true;
    form.clearSensitive();
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown derivation error.';
    form.setError(message);
    hasResults = false;
    output.clear();
    distribution.clear();
    setPipelineState('error');
    progressText.textContent = message;
  } finally {
    form.setBusy(false);
    proof.setBusy(false);
    cracker.setBusy(false);
  }
}

// Any user edit of a derivation input — passphrase, service, username,
// version, length, charset — makes every on-screen result a claim about
// inputs the page no longer holds: the password, its entropy breakdown, the
// DRBG snapshots, the distribution observation, the proof table and the
// "Complete" pipeline state were all computed from the previous values.
// Retire them together. The Break-it panel is the one deliberate exception:
// its armed credential is something an attacker already holds, its verdicts
// name their own service and context, and editing the form does not un-steal
// it — while a NEW derivation re-arms it and discards any in-flight search.
// (form.clearSensitive(), the programmatic wipe after every derivation, fires
// onInputChange but not onEdit, so a run never retires its own results.)
let hasResults = false;
function retireResults(): void {
  if (!hasResults) {
    return;
  }
  hasResults = false;
  output.clear();
  output.setStatus('Inputs changed — derive again.');
  stateDisplay.clear();
  distribution.clear();
  proof.reset();
  resetProgress();
  progressText.textContent = 'Inputs changed — derive again to see results for the new inputs.';
}
form.onEdit(retireResults);

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
