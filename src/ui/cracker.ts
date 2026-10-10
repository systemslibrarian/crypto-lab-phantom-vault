import {
  DEFAULT_WORDLIST,
  crackMasterPassphrase,
  exhaustionTime,
  parseWordlist,
  type CrackOutcome,
  type StolenCredential,
} from '../attack/cracker';
import { buildCharset, validOutputBits } from '../crypto/charset';
import { PBKDF2_ITERATIONS } from '../crypto/pbkdf2';
import { PBKDF2_SEED_BITS } from '../crypto/seed-size';

const ITERATIONS = PBKDF2_ITERATIONS.toLocaleString('en-US');

/**
 * Counted from the live charset, never quoted. The copy here used to say 94;
 * the shipped alphabet is 26 + 26 + 10 + 27 = 89, and interpolating it means
 * adding or removing a symbol cannot leave the prose behind.
 */
const FULL_CHARSET_SIZE = buildCharset({
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
}).length;

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
      passphrase is secret. So an attacker who obtains <strong>one</strong> derived password in
      plaintext — phishing, a keylogger, a shoulder-surf, a site that stored or logged it
      improperly (a well-run site stores only a hash) — can guess passphrases offline: run the
      same public pipeline on each guess and compare. A match is a passphrase consistent with the
      stolen credential. The verdict distinguishes format capacity from the finite seed limit;
      neither proves uniqueness. The candidate can predict other sites' passwords, but those
      predictions need confirmation before treating it as the original passphrase.
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

    <label class="crack-label" for="crack-wordlist">Attacker's wordlist (one candidate per line, trimmed of surrounding whitespace — add your own passphrase and watch it fall)</label>
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
  // Bumped by every arm(). An attack captures the value at launch, and any
  // message it produces later — progress or verdict — is dropped if the panel
  // has since been re-armed. Without this, deriving a new credential while a
  // search is running let the OLD search's verdict land under the NEW armed
  // label: attack A finishes late, and its result overwrites a panel that says
  // it is armed with credential B.
  let generation = 0;

  function syncButton(): void {
    const enabled = stolen !== null && !running && !externallyBusy;
    runButton.disabled = !enabled;
    runButton.setAttribute('aria-disabled', enabled ? 'false' : 'true');
  }

  function arm(next: StolenCredential): void {
    generation += 1;
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

    if (outcome.inconclusive) {
      // The list ran out, but candidates the pipeline refused were never
      // compared — so the search learned nothing about them, and the verdict
      // below must not claim the passphrase is absent from the list.
      resultBox.innerHTML = `
        <p class="crack-verdict crack-held" data-crack-verdict>INCONCLUSIVE — the search reached the end of the
        list, but ${outcome.refusedCandidates} of ${outcome.guessesTried}
        candidate${outcome.guessesTried === 1 ? '' : 's'} never completed a derivation, so
        ${outcome.refusedCandidates === 1 ? 'it was' : 'they were'} never compared against the stolen
        password. Only ${outcome.guessesCompared} guess${outcome.guessesCompared === 1 ? '' : 'es'} were
        actually tested. This is not "the passphrase is not in this list" — the search does not know
        that. Check the wordlist for lines the derivation refuses, and check that this page has
        working WebCrypto.</p>
        ${rateLine}
      `;
      status.textContent = `Attack finished inconclusively: ${outcome.refusedCandidates} of ${outcome.guessesTried} candidates were never compared.`;
      return;
    }

    if (outcome.recovered === null) {
      resultBox.innerHTML = `
        <p class="crack-verdict crack-held" data-crack-verdict>NOT RECOVERED — the wordlist was exhausted after
        ${outcome.guessesTried} guess${outcome.guessesTried === 1 ? '' : 'es'}, every one of them derived and
        compared, without reproducing the
        stolen password. That is the honest outcome of this search, not a proof of safety: it means
        the passphrase behind that password is not in this list. A real attacker's list is billions
        of entries long and is ordered by how often people actually choose each one.</p>
        ${rateLine}
      `;
      status.textContent = `Attack finished: dictionary exhausted after ${outcome.guessesTried} guesses. Master passphrase not recovered.`;
      return;
    }

    const pivot = outcome.pivot;
    // A deterministic map of 2^seedBits possible secret seeds cannot reach more
    // outputs than that. Counting valid format strings only supplies another
    // support ceiling; it supplies neither a distribution nor collision odds.
    const alphabet = charsetSize(credential.charset);
    const formatBits = validOutputBits(credential.charset, credential.length);
    const supportBits = Math.min(formatBits, PBKDF2_SEED_BITS);
    resultBox.innerHTML = `
      <p class="crack-verdict crack-broken" data-crack-verdict>CREDENTIAL-CONSISTENT PASSPHRASE FOUND after
      ${outcome.guessesTried} guess${outcome.guessesTried === 1 ? '' : 'es'}:
      <code class="crack-secret" data-crack-recovered>${escapeHtml(outcome.recovered)}</code></p>
      <p class="crack-detail">Guess ${outcome.guessesTried} reproduced the stolen
      ${credential.length}-character password for "${escapeHtml(credential.service)}" exactly, character
      for character. The derivation is deterministic, so this candidate is not a near miss — but one
      finite output cannot prove it is the <em>only</em> passphrase that produces it.
      Format capacity is <strong data-crack-format>${formatBits.toFixed(1)} bits</strong>
      (${credential.length} characters over ${alphabet} symbols, excluding strings rejected by the
      required-class rule). The reachable-support upper bound is
      <strong data-crack-margin>${supportBits.toFixed(0)} bits</strong>: at most the smaller of
      that format capacity and the ${PBKDF2_SEED_BITS}-bit PBKDF2 seed, with public context fixed.
      This is not a measurement of entropy or a claim that every valid string is reachable.</p>
      <p class="crack-detail">Seed collisions and later mapping collisions can both produce a match.
      This run cannot establish exact collision odds: format counting does not establish uniform
      seeds, uniform output probabilities or the entropy of the master passphrase. No numerical
      collision probability is asserted. A second credential can add evidence, not prove uniqueness.</p>
      ${
        pivot
          ? `<p class="crack-detail">With this credential-consistent candidate the attacker predicts a password for
             <strong data-crack-pivot-service>${escapeHtml(pivot.service)}</strong> — computed here,
             not asserted, but requiring confirmation against that site's credential:
             <code class="crack-secret" data-crack-pivot>${escapeHtml(pivot.password)}</code></p>`
          : ''
      }
      <p class="crack-detail">This is the entropy cap made concrete. Length and charset set the
      <em>format</em> ceiling; they cannot raise the floor. A 64-character password over the full
      ${FULL_CHARSET_SIZE}-symbol charset cannot exceed the secret input's entropy or the
      ${PBKDF2_SEED_BITS}-bit seed ceiling. Actual entropy remains unknown.</p>
      ${rateLine}
    `;
    status.textContent = `Attack finished: a credential-consistent passphrase was found after ${outcome.guessesTried} guesses.`;
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

    // The generation this attack belongs to. If a new derivation re-arms the
    // panel mid-search, everything this attack says from then on — progress
    // lines included — is about a credential the panel no longer holds, and is
    // dropped rather than painted over the new label.
    const launched = generation;
    const stale = (): boolean => launched !== generation;

    void crackMasterPassphrase(credential, wordlist, ({ index, total }) => {
      if (stale()) return;
      status.textContent = `Guess ${index + 1} of ${total} — running the full pipeline (PBKDF2 ${ITERATIONS} iterations, HMAC-DRBG, rejection sampling)…`;
    })
      .then((outcome) => {
        if (stale()) {
          status.textContent =
            'Attack superseded: a new credential was derived while the search ran, so its result was discarded. Run the attack again to test the new one.';
          return;
        }
        renderOutcome(outcome, credential);
      })
      .catch((error: unknown) => {
        if (stale()) return;
        status.textContent = `Attack failed to run: ${error instanceof Error ? error.message : 'unknown error'}`;
      })
      .finally(() => {
        running = false;
        syncButton();
      });
  });

  return { element: wrapper, arm, setBusy };
}
