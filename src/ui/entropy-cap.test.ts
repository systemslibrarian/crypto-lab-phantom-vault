import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import type { CharsetConfig } from '../types/vault';

const dom = new JSDOM('<!doctype html><html><body></body></html>');
(globalThis as unknown as { document: Document }).document = dom.window.document;

const { createEntropyCap, WEAK_PRESET } = await import('./entropy-cap');

const ALL: CharsetConfig = { lowercase: true, uppercase: true, digits: true, symbols: true };

function text(el: HTMLElement, sel: string): string {
  return el.querySelector(sel)?.textContent ?? '';
}

function width(el: HTMLElement, sel: string): number {
  const w = el.querySelector<HTMLElement>(sel)?.style.width ?? '0%';
  return Number.parseFloat(w);
}

test('a weak passphrase pins effective entropy below the ceiling; length/charset only move the ceiling', () => {
  const cap = createEntropyCap();

  // 'password123' scores ~57 bits (upper bound). Both lengths below put the
  // format ceiling ABOVE that, so effective entropy is capped by the passphrase
  // in both cases — cranking length must move only the ceiling bar.
  cap.update({ masterPassphrase: 'password123', length: 20, charset: ALL });
  const effShort = width(cap.element, '#cap-effective-bar');
  const ceilShort = width(cap.element, '#cap-ceiling-bar');

  cap.update({ masterPassphrase: 'password123', length: 64, charset: ALL });
  const effLong = width(cap.element, '#cap-effective-bar');
  const ceilLong = width(cap.element, '#cap-ceiling-bar');

  assert.equal(effShort, effLong, 'effective bar stays pinned by the passphrase');
  assert.ok(ceilLong > ceilShort, 'cranking length raised the ceiling bar');
  assert.ok(ceilLong > effLong, 'ceiling outran the capped effective bar');
  assert.match(text(cap.element, '#cap-verdict'), /Capped/i);
});

test('a strong passphrase makes the output format the limiter (not capped)', () => {
  const cap = createEntropyCap();
  cap.update({
    masterPassphrase: 'Tr0ub4dour&3-correct-horse-battery-staple-XYZ',
    length: 12,
    charset: ALL,
  });
  assert.match(text(cap.element, '#cap-verdict'), /Not capped/i);
});

/**
 * Regression — the "Not capped" branch endorsed the passphrase.
 *
 * Its copy read "This passphrase (N bits upper bound) is not what's holding you
 * back". Measured against the shipped default wordlist at the shipped charset:
 * that verdict fires for `password123` at length 8 (the form minimum, and the
 * phrase behind this panel's own preset button) and for "correct horse battery
 * staple" across lengths 8-25. Both fall to the Break-it panel's default list.
 *
 * The claim under test: neither verdict branch may state the composition bound
 * as a measurement or as a reason to stop worrying about the passphrase.
 */
test('no verdict branch endorses a passphrase the Break-it panel can crack', async () => {
  const { DEFAULT_WORDLIST } = await import('../attack/cracker');
  const cap = createEntropyCap();

  const forbidden = [
    "is not what's holding you back",
    'pins effective strength',
  ];

  let capped = 0;
  let notCapped = 0;
  for (const phrase of DEFAULT_WORDLIST) {
    for (let length = 8; length <= 64; length += 1) {
      cap.update({ masterPassphrase: phrase, length, charset: ALL });
      const verdict = text(cap.element, '#cap-verdict');
      assert.ok(verdict.length > 0, 'a verdict was rendered');
      for (const phraseToBan of forbidden) {
        assert.ok(
          !verdict.includes(phraseToBan),
          `"${phrase}" at length ${length} drew: ${verdict}`,
        );
      }
      if (/^Not capped/.test(verdict)) {
        notCapped += 1;
        // The branch that used to endorse now has to name the bound's nature.
        assert.match(verdict, /not a measurement/i, verdict);
        assert.match(verdict, /Break-it panel/i, verdict);
      } else {
        capped += 1;
        assert.match(verdict, /no more than/i, verdict);
      }
    }
  }

  // Both branches must actually have been reached, or this asserts nothing.
  assert.ok(capped > 0, 'the capped branch was exercised');
  assert.ok(notCapped > 0, `the "Not capped" branch was exercised (saw ${notCapped} cases)`);
});

test('empty passphrase hides the cap line and shows a prompt', () => {
  const cap = createEntropyCap();
  cap.update({ masterPassphrase: '', length: 20, charset: ALL });
  const line = cap.element.querySelector<HTMLElement>('#cap-line');
  assert.equal(line?.style.opacity, '0');
  assert.match(text(cap.element, '#cap-caption'), /Type a master passphrase/i);
});

test('the weak preset cranks every knob yet stays weak by design', () => {
  assert.equal(WEAK_PRESET.length, 64);
  assert.deepEqual(WEAK_PRESET.charset, ALL);
  assert.equal(WEAK_PRESET.masterPassphrase, 'password123');
});

test('onWeakPreset fires the registered handler when the button is clicked', () => {
  const cap = createEntropyCap();
  let fired = 0;
  cap.onWeakPreset(() => {
    fired += 1;
  });
  cap.element.querySelector<HTMLButtonElement>('#cap-weak-preset')?.click();
  assert.equal(fired, 1);
});
