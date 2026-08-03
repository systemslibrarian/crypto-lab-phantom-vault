import {
  DEFAULT_WORDLIST,
  crackMasterPassphrase,
  exhaustionTime,
  parseWordlist,
  type CrackOutcome,
  type StolenCredential,
} from '../attack/cracker';
import { buildCharset } from '../crypto/charset';
import { PBKDF2_ITERATIONS } from '../crypto/pbkdf2';

const ITERATIONS = PBKDF2_ITERATIONS.toLocaleString('en-US');

export interface CrackerController {
  element: HTMLElement;
  /** Arm the panel with what an attacker would hold after a real derivation. */
  arm: (stolen: StolenCredential) => void;
  /** Disarm while the main pipeline is running. */
  setBusy: (busy: boolean) => void;
}

function requireNode<T extends Element>(parent: ParentNode, selector: string): T {
  const node = parent.querySelector<T>(selector);
  if (!node) {
    throw new Error(`Missing cracker node: ${selector}`);
  }
  return node;
}

function charsetSize(config: StolenCredential['charset']): number {
  try {
    return buildCharset(config).length;
  } catch {
    return 0;
  }
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function createCracker(): CrackerController {
  const wrapper = document.createElement('section');
  wrapper.className = 'panel';

  wrapper.innerHTML = `
    <h2 class="panel-title">Break it — crack the master passphrase</h2>
    <p class="helper-text">
      Everything about this derivation is public: the algorithm, the ${ITERATIONS} PBKDF2
      iterations, the service, the username, the version, the charset, the length. Only the master
      passphrase is secret. So an attacker who steals <strong>one</strong> derived password can
      guess passphrases offline: run the same public pipeline on each guess and compare. A match is
      not a likely match — it is the passphrase, and every other site's password follows.
      This panel is handed exactly what such an attacker holds. Your passphrase is cleared from
      the form the moment a derivation finishes, and the search below never sees it.
    </p>
    <p class="helper-text crack-scale">
      <strong>Scale note.</strong> This is a toy search: ${DEFAULT_WORDLIST.length} candidates by
      default, run one at a time in a single browser tab. Real offline cracking uses dictionaries of
      billions of entries ordered by how often people pick them, mutation rules on top of those, and
      GPUs running thousands of candidates in parallel. Everything below is computed for real at
      that toy scale — treat the guess rate it reports as a floor on an attacker's speed, never an
      estimate of it.
    </p>
    <p class="helper-text" id="crack-armed" aria-live="polite">Derive a password first — the attack needs a stolen credential to work against.</p>

    <label class="crack-label" for="crack-wordlist">Attacker's wordlist (one candidate per line — add your own passphrase and watch it fall)</label>
    <textarea id="crack-wordlist" class="crack-wordlist" rows="6" spellcheck="false">${escapeHtml(DEFAULT_WORDLIST.join('\n'))}</textarea>

    <button type="button" class="action-button" id="crack-run" disabled aria-disabled="true">Run the attack</button>

    <p id="crack-status" class="proof-result" aria-live="polite" role="status">Idle.</p>
    <div id="crack-result" class="crack-result"></div>
  `;

  const armedNote = requireNode<HTMLElement>(wrapper, '#crack-armed');
  const wordlistBox = requireNode<HTMLTextAreaElement>(wrapper, '#crack-wordlist');
  const runButton = requireNode<HTMLButtonElement>(wrapper, '#crack-run');
  const status = requireNode<HTMLElement>(wrapper, '#crack-status');
  const resultBox = requireNode<HTMLElement>(wrapper, '#crack-result');

  let stolen: StolenCredential | null = null;
  let running = false;
  let externallyBusy = false;

  function syncButton(): void {
    const enabled = stolen !== null && !running && !externallyBusy;
    runButton.disabled = !enabled;
    runButton.setAttribute('aria-disabled', enabled ? 'false' : 'true');
  }

  function arm(next: StolenCredential): void {
    stolen = next;
    armedNote.textContent =
      `Armed. The attacker holds the ${next.length}-character password just derived for ` +
      `"${next.service}" (username "${next.username}", version ${next.version}), plus the ` +
      `public derivation parameters. Not the passphrase.`;
    resultBox.innerHTML = '';
    status.textContent = 'Ready to run.';
    syncButton();
  }

  function setBusy(busy: boolean): void {
    externallyBusy = busy;
    syncButton();
  }

  function renderOutcome(outcome: CrackOutcome, credential: StolenCredential): void {
    const rate = outcome.guessesPerSecond;
    const rateLine =
      `<p class="crack-metric">Measured in this tab: <strong>${outcome.guessesTried}</strong> full ` +
      `derivations in <strong>${outcome.elapsedMs} ms</strong> — ` +
      `<strong>${rate.toFixed(2)} guesses/second</strong>. That rate is what ${ITERATIONS} PBKDF2 ` +
      `iterations buys: at it, exhausting a 40-bit passphrase would take ${exhaustionTime(40, rate)}, ` +
      `and a 60-bit one ${exhaustionTime(60, rate)}. A browser tab is the slowest attacker there is; ` +
      `dedicated hardware runs this same search far faster, so treat these as a floor on the ` +
      `attacker's speed rather than an estimate of it.</p>`;

    if (outcome.recovered === null) {
      resultBox.innerHTML = `
        <p class="crack-verdict crack-held" data-crack-verdict>NOT RECOVERED — the wordlist was exhausted after
        ${outcome.guessesTried} guess${outcome.guessesTried === 1 ? '' : 'es'} without reproducing the
        stolen password. That is the honest outcome of this search, not a proof of safety: it means
        the passphrase behind that password is not in this list. A real attacker's list is billions
        of entries long and is ordered by how often people actually choose each one.</p>
        ${rateLine}
      `;
      status.textContent = `Attack finished: dictionary exhausted after ${outcome.guessesTried} guesses. Master passphrase not recovered.`;
      return;
    }

    const pivot = outcome.pivot;
    // How improbable a false match would be, computed from this run's own
    // format: any wrong passphrase would have to reproduce all `length`
    // characters over the selected alphabet. Stated rather than hand-waved,
    // because "a match IS the passphrase" is only true to within this margin.
    const alphabet = charsetSize(credential.charset);
    const matchBits = alphabet > 1 ? Math.log2(alphabet) * credential.length : 0;
    resultBox.innerHTML = `
      <p class="crack-verdict crack-broken" data-crack-verdict>MASTER PASSPHRASE RECOVERED after
      ${outcome.guessesTried} guess${outcome.guessesTried === 1 ? '' : 'es'}:
      <code class="crack-secret" data-crack-recovered>${escapeHtml(outcome.recovered)}</code></p>
      <p class="crack-detail">Guess ${outcome.guessesTried} reproduced the stolen
      ${credential.length}-character password for "${escapeHtml(credential.service)}" exactly, character
      for character. The derivation is deterministic, so this is a recovery rather than a guess at
      one: for a <em>wrong</em> passphrase to land here it would have to collide across all
      ${credential.length} characters of a ${alphabet}-symbol alphabet, about
      ${matchBits.toFixed(0)} bits of agreement by chance.</p>
      ${
        pivot
          ? `<p class="crack-detail">And the damage does not stop at the stolen site. With that
             passphrase the same attacker immediately derives your password for
             <strong data-crack-pivot-service>${escapeHtml(pivot.service)}</strong> — computed here,
             not asserted:
             <code class="crack-secret" data-crack-pivot>${escapeHtml(pivot.password)}</code></p>`
          : ''
      }
      <p class="crack-detail">This is the entropy cap made concrete. Length and charset set the
      <em>format</em> ceiling; they cannot raise the floor. A 64-character password over 94 symbols
      is worth exactly as much as the passphrase behind it.</p>
      ${rateLine}
    `;
    status.textContent = `Attack finished: master passphrase recovered after ${outcome.guessesTried} guesses.`;
  }

  runButton.addEventListener('click', () => {
    if (running || stolen === null) return;
    const credential = stolen;
    const wordlist = parseWordlist(wordlistBox.value);
    if (wordlist.length === 0) {
      status.textContent = 'The wordlist is empty — add at least one candidate passphrase.';
      return;
    }

    running = true;
    syncButton();
    resultBox.innerHTML = '';
    status.textContent = `Running ${wordlist.length} full derivations…`;

    void crackMasterPassphrase(credential, wordlist, ({ index, total }) => {
      status.textContent = `Guess ${index + 1} of ${total} — running the full pipeline (PBKDF2 ${ITERATIONS} iterations, HMAC-DRBG, rejection sampling)…`;
    })
      .then((outcome) => {
        renderOutcome(outcome, credential);
      })
      .catch((error: unknown) => {
        status.textContent = `Attack failed to run: ${error instanceof Error ? error.message : 'unknown error'}`;
      })
      .finally(() => {
        running = false;
        syncButton();
      });
  });

  return { element: wrapper, arm, setBusy };
}
