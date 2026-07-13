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
