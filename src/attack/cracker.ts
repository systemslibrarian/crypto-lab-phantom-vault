import { derivePassword } from '../derive/pipeline';
import type { CharsetConfig, VaultInputs } from '../types/vault';

/**
 * The adversary this demo was missing.
 *
 * Everything about the derivation is public: the algorithm, the iteration
 * count, the service, the username, the version, the charset, the length. The
 * one secret is the master passphrase. So an attacker who steals a SINGLE
 * derived password — from a breached site, a shoulder-surf, a reused login —
 * can mount a straightforward offline attack: guess a passphrase, run the same
 * public derivation, and compare the output to the password they hold. A match
 * is not a probable match; it is the passphrase, and with it every other site's
 * password this vault would ever produce.
 *
 * This is the entropy-cap panel's claim made falsifiable. That panel asserts
 * that a weak passphrase caps effective strength no matter how long or exotic
 * the output format is. Here, a 64-character password over the full 94-symbol
 * charset falls in a handful of guesses when the passphrase behind it is
 * `password123`, and the same run against a strong passphrase exhausts the list
 * and reports nothing recovered.
 *
 * Nothing is simulated: every guess runs the real pipeline (PBKDF2 at the
 * shipped iteration count, HMAC-DRBG, rejection sampling) and compares the real
 * derived string.
 */

/** Exactly what an attacker holds: one derived password and its public context. */
export interface StolenCredential {
  password: string;
  service: string;
  username: string;
  version: number;
  length: number;
  charset: CharsetConfig;
}

export interface CrackProgress {
  guess: string;
  index: number;
  total: number;
}

export interface CrackOutcome {
  /** How many candidate passphrases were actually run through the pipeline. */
  guessesTried: number;
  elapsedMs: number;
  /** Measured in this browser tab, from this run — not quoted from anywhere. */
  guessesPerSecond: number;
  /** The passphrase, when a guess reproduced the stolen password exactly. */
  recovered: string | null;
  /**
   * Consequence, computed rather than asserted: the password the same attacker
   * now derives for a DIFFERENT service, using only the cracked passphrase.
   */
  pivot: { service: string; password: string } | null;
  /** True when the whole list ran without a match. */
  exhausted: boolean;
}

/**
 * A short list of passphrases that appear at the top of every leaked-credential
 * corpus. It is deliberately tiny — the point is the cost per guess, not the
 * size of the dictionary — and the UI lets the learner add their own.
 */
export const DEFAULT_WORDLIST = [
  'letmein',
  'qwerty123',
  'iloveyou',
  'correct horse battery staple',
  'password123',
  'admin1234',
  'trustno1',
  'hunter2',
];

/** Parse the learner-editable wordlist box: one candidate per line, no blanks. */
export function parseWordlist(raw: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of raw.split('\n')) {
    const candidate = line.trim();
    if (candidate.length === 0 || seen.has(candidate)) continue;
    seen.add(candidate);
    out.push(candidate);
  }
  return out;
}

/** A second service to pivot to, guaranteed different from the stolen one. */
export function pivotService(service: string): string {
  return service === 'bank.example' ? 'mail.example' : 'bank.example';
}

export type DeriveFn = typeof derivePassword;

export async function crackMasterPassphrase(
  stolen: StolenCredential,
  wordlist: string[],
  onProgress: (progress: CrackProgress) => void = () => {},
  derive: DeriveFn = derivePassword,
): Promise<CrackOutcome> {
  const silent = (): void => {};
  const started = Date.now();
  let guessesTried = 0;
  let recovered: string | null = null;

  for (const [index, guess] of wordlist.entries()) {
    onProgress({ guess, index, total: wordlist.length });
    const attempt: VaultInputs = {
      masterPassphrase: guess,
      service: stolen.service,
      username: stolen.username,
      version: stolen.version,
      length: stolen.length,
      charset: stolen.charset,
    };
    guessesTried += 1;
    let produced: string;
    try {
      produced = (await derive(attempt, silent)).password;
    } catch {
      // A candidate the pipeline refuses (e.g. an empty passphrase) is simply a
      // guess that did not work; it must not abort the search.
      continue;
    }
    if (produced === stolen.password) {
      recovered = guess;
      break;
    }
  }

  const elapsedMs = Math.max(1, Date.now() - started);
  const guessesPerSecond = (guessesTried * 1000) / elapsedMs;

  let pivot: CrackOutcome['pivot'] = null;
  if (recovered !== null) {
    // The consequence, run for real: same attacker, same public algorithm, a
    // different site. No ground truth is needed — the passphrase was proven
    // correct by reproducing the stolen password byte for byte above.
    const service = pivotService(stolen.service);
    const other = await derive(
      {
        masterPassphrase: recovered,
        service,
        username: stolen.username,
        version: stolen.version,
        length: stolen.length,
        charset: stolen.charset,
      },
      silent,
    );
    pivot = { service, password: other.password };
  }

  return {
    guessesTried,
    elapsedMs,
    guessesPerSecond,
    recovered,
    pivot,
    exhausted: recovered === null,
  };
}

/**
 * Time to exhaust a search space of `bits` at a measured rate, as a human
 * string. Used only with rates this page actually measured.
 */
export function exhaustionTime(bits: number, guessesPerSecond: number): string {
  if (guessesPerSecond <= 0 || !Number.isFinite(guessesPerSecond)) return 'unknown';
  const seconds = Math.pow(2, bits) / guessesPerSecond;
  const units: Array<[number, string]> = [
    [1, 'seconds'],
    [60, 'minutes'],
    [3600, 'hours'],
    [86_400, 'days'],
    [31_557_600, 'years'],
  ];
  let value = seconds;
  let label = 'seconds';
  for (const [divisor, name] of units) {
    const scaled = seconds / divisor;
    if (scaled >= 1) {
      value = scaled;
      label = name;
    }
  }
  if (label === 'years' && value >= 1e6) {
    return `${value.toExponential(2)} years`;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value).toLocaleString('en-US')} ${label}`;
}
