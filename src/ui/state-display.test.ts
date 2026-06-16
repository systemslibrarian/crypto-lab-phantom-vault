import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import type { DRBGState } from '../types/vault';

const dom = new JSDOM('<!doctype html><html><body></body></html>');
(globalThis as unknown as { document: Document }).document = dom.window.document;

const { createStateDisplay } = await import('./state-display');

const STATES: DRBGState[] = [
  { K: 'a'.repeat(64), V: 'b'.repeat(64), reseedCounter: 1 },
  { K: 'c'.repeat(64), V: 'd'.repeat(64), reseedCounter: 2 },
];

test('renders one card per DRBG snapshot plus a byte-accounting summary', () => {
  const display = createStateDisplay();
  display.setStates(STATES, 64, 12);

  const items = display.element.querySelectorAll('.state-item');
  assert.equal(items.length, 2);
  assert.match(items[0].textContent ?? '', /Instantiate/);
  assert.match(items[1].textContent ?? '', /Generate/);

  const summary = display.element.querySelector('.state-summary')?.textContent ?? '';
  assert.match(summary, /64 bytes generated/);
  assert.match(summary, /12 rejected/);
});

test('setStates is idempotent — re-rendering does not stack duplicate cards', () => {
  const display = createStateDisplay();
  display.setStates(STATES, 64, 12);
  display.setStates(STATES, 64, 12);
  assert.equal(display.element.querySelectorAll('.state-item').length, 2);
});

test('includes the rejection-sampling / modulo-bias explainer for learners', () => {
  const display = createStateDisplay();
  const html = display.element.innerHTML;
  assert.match(html, /modulo bias/i);
  assert.match(html, /Why are bytes rejected/i);
});
