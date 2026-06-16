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

  // effective = min(129.5, 500) = 129.5 -> "Very Strong", meter at 100%.
  assert.equal(text(out.element, '#entropy-effective'), '129.5 bits');
  assert.equal(text(out.element, '#strength-label'), 'Strength: Very Strong');
  assert.equal(
    out.element.querySelector('#strength-track')?.getAttribute('aria-valuenow'),
    '100',
  );
  assert.match(text(out.element, '#entropy-note'), /output format/i);
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
