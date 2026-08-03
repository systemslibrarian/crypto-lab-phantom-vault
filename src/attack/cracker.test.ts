import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  DEFAULT_WORDLIST,
  crackMasterPassphrase,
  exhaustionTime,
  parseWordlist,
  pivotService,
  type CrackProgress,
  type DeriveFn,
  type StolenCredential,
} from './cracker';
import { derivePassword } from '../derive/pipeline';
import { WEAK_PRESET } from '../ui/entropy-cap';
import type { VaultInputs } from '../types/vault';

// Every test below runs the real derivation pipeline (PBKDF2 at the shipped
// iteration count, HMAC-DRBG, rejection sampling). Nothing here stubs the
// derivation, because the whole claim of the exhibit is that a guess is checked
// by *reproducing* the stolen password, not by any cheaper proxy.

const silent = (): void => {};

const TRUE_PASSPHRASE = 'trustno1';

const VICTIM: VaultInputs = {
  masterPassphrase: TRUE_PASSPHRASE,
  service: 'github.com',
  username: 'you@example.com',
  version: 1,
  length: 20,
  charset: { lowercase: true, uppercase: true, digits: true, symbols: true },
};

// Derived once: this is the single artefact the attacker is assumed to have
// stolen. The passphrase never crosses into `STOLEN`.
const victimResult = await derivePassword(VICTIM, silent);

const STOLEN: StolenCredential = {
  password: victimResult.password,
  service: VICTIM.service,
  username: VICTIM.username,
  version: VICTIM.version,
  length: VICTIM.length,
  charset: VICTIM.charset,
};

test('parseWordlist trims, drops blanks, dedupes, and preserves order', () => {
  const parsed = parseWordlist('  letmein \n\n\thunter2\nletmein\n   \nqwerty123\n');
  assert.deepEqual(parsed, ['letmein', 'hunter2', 'qwerty123']);
  assert.deepEqual(parseWordlist('   \n\n  '), []);
});

test('pivotService always names a service different from the stolen one', () => {
  assert.notEqual(pivotService('github.com'), 'github.com');
  assert.notEqual(pivotService('bank.example'), 'bank.example');
  assert.notEqual(pivotService('mail.example'), 'mail.example');
});

test('exhaustionTime scales a measured rate into human units', () => {
  assert.equal(exhaustionTime(40, 0), 'unknown');
  assert.equal(exhaustionTime(40, Number.NaN), 'unknown');
  // 2^0 guesses at 1 guess/second.
  assert.equal(exhaustionTime(0, 1), '1.0 seconds');
  // 2^10 = 1024 seconds at 1 guess/second = 17.07 minutes.
  assert.equal(exhaustionTime(10, 1), '17 minutes');
  // 2^60 at 1 guess/second is far past a million years, so it goes exponential.
  assert.match(exhaustionTime(60, 1), /^\d\.\d{2}e\+\d+ years$/);
});

test('the shipped wordlist actually contains the weak preset the page invites you to try', () => {
  // The entropy-cap panel offers "try a weak passphrase" and the attack panel
  // promises it falls. If these two ever drift apart the exhibit lies.
  assert.ok(DEFAULT_WORDLIST.includes(WEAK_PRESET.masterPassphrase));
  assert.deepEqual(parseWordlist(DEFAULT_WORDLIST.join('\n')), DEFAULT_WORDLIST);
});

test('success path: a passphrase in the wordlist is recovered, and the pivot is really derived', async () => {
  const seen: CrackProgress[] = [];
  const wordlist = ['not-the-one', 'also-not-the-one', TRUE_PASSPHRASE];

  const outcome = await crackMasterPassphrase(STOLEN, wordlist, (progress) => {
    seen.push(progress);
  });

  assert.equal(outcome.recovered, TRUE_PASSPHRASE);
  assert.equal(outcome.exhausted, false);
  // It stopped at the match rather than running the whole list.
  assert.equal(outcome.guessesTried, 3);
  // Every guess up to the match was genuinely attempted.
  assert.deepEqual(
    seen.map((p) => p.guess),
    wordlist,
  );
  assert.ok(outcome.guessesPerSecond > 0 && Number.isFinite(outcome.guessesPerSecond));

  // The pivot is the consequence, and it must be a real derivation for a real
  // second service — not a copy of the stolen password and not a placeholder.
  assert.ok(outcome.pivot);
  const pivot = outcome.pivot;
  assert.notEqual(pivot.service, STOLEN.service);
  assert.equal(pivot.password.length, STOLEN.length);
  assert.notEqual(pivot.password, STOLEN.password);

  const independent = await derivePassword(
    { ...VICTIM, service: pivot.service },
    silent,
  );
  assert.equal(pivot.password, independent.password);
});

test('failure path: a wordlist without the passphrase exhausts and recovers nothing', async () => {
  const seen: CrackProgress[] = [];
  const wordlist = ['nope-one', 'nope-two', 'nope-three'];

  const outcome = await crackMasterPassphrase(STOLEN, wordlist, (progress) => {
    seen.push(progress);
  });

  assert.equal(outcome.recovered, null);
  assert.equal(outcome.exhausted, true);
  assert.equal(outcome.pivot, null);
  // The whole list ran; nothing short-circuited the search into a fake miss.
  assert.equal(outcome.guessesTried, wordlist.length);
  assert.deepEqual(
    seen.map((p) => p.guess),
    wordlist,
  );
  assert.deepEqual(
    seen.map((p) => p.total),
    [3, 3, 3],
  );
});

test('the right passphrase under the wrong public context still fails', async () => {
  // Proves the comparison is against a re-derived password, not membership in a
  // list: same true passphrase, one field of public context changed, no match.
  const wrongContext: StolenCredential = { ...STOLEN, service: 'gitlab.example' };
  const outcome = await crackMasterPassphrase(wrongContext, [TRUE_PASSPHRASE]);

  assert.equal(outcome.recovered, null);
  assert.equal(outcome.exhausted, true);
  assert.equal(outcome.guessesTried, 1);
});

test('a candidate the pipeline refuses is a miss, not an abort', async () => {
  // An empty passphrase makes derivePassword throw. The search must count it and
  // keep going, otherwise one bad line in the box silently ends the attack.
  const outcome = await crackMasterPassphrase(STOLEN, ['', TRUE_PASSPHRASE]);

  assert.equal(outcome.recovered, TRUE_PASSPHRASE);
  assert.equal(outcome.guessesTried, 2);
  assert.equal(outcome.exhausted, false);
});

// ---------------------------------------------------------------------------
// The exhibit's load-bearing claim is not "the cracker works" — it is that the
// cracker only ever holds what a real attacker holds. An attack panel that
// quietly reads the secret it is supposed to be searching for would still pass
// every test above, because it would still recover the right passphrase. These
// tests exist to make that failure mode impossible to hide.
// ---------------------------------------------------------------------------

test('the stolen credential carries no passphrase field at all', () => {
  // Guards the shape the UI hands over (src/main.ts builds exactly this object).
  assert.deepEqual(Object.keys(STOLEN).sort(), [
    'charset',
    'length',
    'password',
    'service',
    'username',
    'version',
  ]);
  // Nothing anywhere in the credential encodes the secret, including as a
  // substring of some other field.
  assert.ok(!JSON.stringify(STOLEN).includes(TRUE_PASSPHRASE));
});

test('even if the passphrase is smuggled onto the credential, the search never uses it', async () => {
  // The strongest form of the claim. Contaminate the credential with the real
  // passphrase, then run a wordlist that does NOT contain it. If any code path
  // reads the secret rather than searching for it, this recovers and fails here.
  const contaminated = {
    ...STOLEN,
    masterPassphrase: TRUE_PASSPHRASE,
  } as StolenCredential;

  const outcome = await crackMasterPassphrase(contaminated, ['nope-one', 'nope-two']);

  assert.equal(outcome.recovered, null);
  assert.equal(outcome.exhausted, true);
  assert.equal(outcome.pivot, null);
  assert.equal(outcome.guessesTried, 2);
});

test('every derivation the search runs uses a wordlist candidate as the passphrase', async () => {
  // Records exactly what reaches the pipeline. The passphrase side of each call
  // must come from the wordlist and nowhere else; the public context must be
  // the stolen credential's, unchanged.
  const calls: VaultInputs[] = [];
  const spy: DeriveFn = async (inputs, onProgress) => {
    calls.push({ ...inputs });
    return derivePassword(inputs, onProgress);
  };

  const wordlist = ['first-miss', 'second-miss', TRUE_PASSPHRASE];
  const outcome = await crackMasterPassphrase(STOLEN, wordlist, () => {}, spy);
  assert.equal(outcome.recovered, TRUE_PASSPHRASE);

  // Three search derivations, then one more for the pivot consequence.
  assert.equal(calls.length, 4);

  const searchCalls = calls.slice(0, 3);
  assert.deepEqual(
    searchCalls.map((c) => c.masterPassphrase),
    wordlist,
  );
  for (const call of searchCalls) {
    assert.equal(call.service, STOLEN.service);
    assert.equal(call.username, STOLEN.username);
    assert.equal(call.version, STOLEN.version);
    assert.equal(call.length, STOLEN.length);
    assert.deepEqual(call.charset, STOLEN.charset);
  }

  // The pivot re-uses the RECOVERED passphrase against a different service. It
  // is allowed to know the secret only because the search just proved it.
  const pivotCall = calls[3];
  assert.equal(pivotCall.masterPassphrase, TRUE_PASSPHRASE);
  assert.notEqual(pivotCall.service, STOLEN.service);
  assert.equal(pivotCall.service, pivotService(STOLEN.service));
});

test('a failed search runs the pipeline once per candidate and never once more', async () => {
  // On the failure path there is no pivot, so the derivation count must equal
  // the wordlist length exactly — no extra call sneaking in a known-good guess.
  const calls: VaultInputs[] = [];
  const spy: DeriveFn = async (inputs, onProgress) => {
    calls.push({ ...inputs });
    return derivePassword(inputs, onProgress);
  };

  const wordlist = ['miss-one', 'miss-two', 'miss-three'];
  const outcome = await crackMasterPassphrase(STOLEN, wordlist, () => {}, spy);

  assert.equal(outcome.recovered, null);
  assert.equal(calls.length, wordlist.length);
  assert.deepEqual(
    calls.map((c) => c.masterPassphrase),
    wordlist,
  );
  assert.ok(!calls.some((c) => c.masterPassphrase === TRUE_PASSPHRASE));
});

test('a truncated or altered stolen password is never matched', async () => {
  // Guards the comparison against being loosened to a prefix/substring test.
  const truncated: StolenCredential = {
    ...STOLEN,
    password: STOLEN.password.slice(0, STOLEN.length - 1),
  };
  const outcome = await crackMasterPassphrase(truncated, [TRUE_PASSPHRASE]);

  assert.equal(outcome.recovered, null);
  assert.equal(outcome.exhausted, true);
});
