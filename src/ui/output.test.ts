import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>');
(globalThis as unknown as { document: Document }).document = dom.window.document;
(globalThis as unknown as { window: unknown }).window = dom.window;

const { createOutput } = await import('./output');

function text(el: HTMLElement, sel: string): string {
  return el.querySelector(sel)?.textContent ?? '';
}

test('weak passphrase caps the effective entropy below the format ceiling', () => {
  const out = createOutput();
  // ceiling = 20 * log2(89) ≈ 129.5 bits; passphrase upper bound = 30 bits.
  out.setOutput('Ab1!Ab1!Ab1!Ab1!Ab12', 89, 20, 30);

  assert.equal(text(out.element, '#entropy-effective'), '30.0 bits');
  assert.ok(text(out.element, '#entropy-ceiling').includes('129.5 bits'));
  assert.ok(text(out.element, '#entropy-ceiling').includes('log₂ 89'));
  assert.equal(text(out.element, '#entropy-passphrase'), '30.0 bits');
  // The note must call out the passphrase as the limiter.
  assert.match(text(out.element, '#entropy-note'), /master passphrase/i);
  // 30 bits -> "Weak", meter at 25%.
  assert.equal(text(out.element, '#strength-label'), 'Strength: Weak');
  const track = out.element.querySelector('#strength-track');
  assert.equal(track?.getAttribute('aria-valuenow'), '25');
  assert.match(track?.getAttribute('aria-valuetext') ?? '', /Weak/);
});

test('strong passphrase makes the output format the limiter', () => {
  const out = createOutput();
  out.setOutput('whatever-the-password-is', 89, 20, 500);

  // effective = min(129.5, 500) = 129.5, meter at 100%.
  assert.equal(text(out.element, '#entropy-effective'), '129.5 bits');
  assert.equal(
    out.element.querySelector('#strength-track')?.getAttribute('aria-valuenow'),
    '100',
  );
  assert.match(text(out.element, '#entropy-note'), /output format/i);
});

/**
 * Regression — the page rated passphrases its own Break-it panel cracks.
 *
 * `effectiveBits` is min(format ceiling, composition ceiling). Both terms are
 * ceilings, so the number can prove a passphrase weak and can never prove one
 * strong. Printed as "Strength: Fair" it did the latter: measured over the
 * shipped DEFAULT_WORDLIST at the shipped form defaults, 5 of its 8 entries
 * score better than Weak, including "password123" (56.9 bits -> "Fair", cracked
 * at guess 5 of 8) and "correct horse battery staple" (129.5 bits -> "Very
 * Strong", cracked at guess 4 of 8). The page's own preset button types the
 * first of those in.
 *
 * The claim under test is the ENTAILMENT, not the wording: a bound above the
 * Weak band may be stated as a limit and never as a verdict.
 */
test('no upper bound above the Weak band is ever printed as a positive verdict', () => {
  const capped: string[] = [];
  const asserted: string[] = [];

  // Sweep the whole range the page can print, in both the capped and
  // format-limited directions, so neither branch escapes.
  for (let bits = 1; bits <= 400; bits += 1) {
    for (const [passphraseBits, ceilingSize, ceilingLen] of [
      [bits, 89, 64] as const, // passphrase-capped: effective = bits
      [10_000, 89, Math.max(1, Math.round(bits / Math.log2(89)))] as const, // format-capped
    ]) {
      const out = createOutput();
      out.setOutput('x'.repeat(ceilingLen), ceilingSize, ceilingLen, passphraseBits);
      const label = text(out.element, '#strength-label');
      const valueText =
        out.element.querySelector('#strength-track')?.getAttribute('aria-valuetext') ?? '';
      const live = text(out.element, '#output-live');
      const effective = Number(text(out.element, '#entropy-effective').replace(' bits', ''));

      if (effective < 40) {
        assert.equal(label, 'Strength: Weak', `${effective} bits must read Weak`);
        asserted.push(label);
      } else {
        // Above the Weak band the number is a ceiling and must be worded as one,
        // on every surface that carries it — including the screen-reader ones.
        assert.match(label, /^Strength: at most /, `${effective} bits printed as a verdict: ${label}`);
        assert.match(valueText, /^at most /, `aria-valuetext states a verdict: ${valueText}`);
        assert.match(live, /Upper bound only/, `live region states a verdict: ${live}`);
        capped.push(label);
      }
    }
  }

  // Non-vacuous on both sides: the sweep really visited both bands.
  assert.ok(asserted.length > 0, 'the Weak band was exercised');
  assert.ok(capped.length > 0, 'the above-Weak bands were exercised');
  assert.ok(
    new Set(capped).size >= 3,
    `every above-Weak band was exercised, saw: ${[...new Set(capped)].join(' | ')}`,
  );
});

/**
 * The concrete instance of the above, tied to the shipped constants rather than
 * to a number typed into this test: every entry of the default wordlist is a
 * passphrase this page can crack, so none of them may draw a positive verdict.
 */
test('no shipped wordlist passphrase draws a positive strength verdict', async () => {
  const { DEFAULT_WORDLIST } = await import('../attack/cracker');
  const { estimatePassphraseEntropyBits } = await import('../crypto/charset');

  let aboveWeak = 0;
  for (const phrase of DEFAULT_WORDLIST) {
    const out = createOutput();
    const bits = estimatePassphraseEntropyBits(phrase);
    out.setOutput('x'.repeat(20), 89, 20, bits);
    const label = text(out.element, '#strength-label');
    assert.ok(
      label === 'Strength: Weak' || label.startsWith('Strength: at most '),
      `"${phrase}" (${bits.toFixed(1)} bits) is cracked by this page's own wordlist but reads ${label}`,
    );
    if (label !== 'Strength: Weak') aboveWeak += 1;
  }

  // If the composition score ever stopped putting these above the Weak band the
  // test would be testing nothing, so require that it still does.
  assert.ok(
    aboveWeak >= 4,
    `expected several wordlist entries to score above Weak (the whole point), saw ${aboveWeak}`,
  );
});

test('the derived password is held in a password-type field, not shown in cleartext', () => {
  const out = createOutput();
  out.setOutput('s3cr3t-derived-value', 89, 20, 200);
  const input = out.element.querySelector<HTMLInputElement>('#password-value');
  assert.equal(input?.value, 's3cr3t-derived-value');
  assert.equal(input?.type, 'password');
});

test('clear() resets the readout and the progressbar ARIA state', () => {
  const out = createOutput();
  out.setOutput('Ab1!Ab1!Ab1!Ab1!Ab12', 89, 20, 30);
  out.clear();

  assert.equal(text(out.element, '#entropy-effective'), 'n/a');
  assert.equal(text(out.element, '#entropy-ceiling'), 'n/a');
  assert.equal(text(out.element, '#entropy-passphrase'), 'n/a');
  const track = out.element.querySelector('#strength-track');
  assert.equal(track?.getAttribute('aria-valuenow'), '0');
  assert.equal(track?.getAttribute('aria-valuetext'), null);
});

test('strength progressbar exposes the required ARIA range attributes', () => {
  const track = createOutput().element.querySelector('#strength-track');
  assert.equal(track?.getAttribute('role'), 'progressbar');
  assert.equal(track?.getAttribute('aria-valuemin'), '0');
  assert.equal(track?.getAttribute('aria-valuemax'), '100');
  assert.ok((track?.getAttribute('aria-label') ?? '').length > 0);
});
