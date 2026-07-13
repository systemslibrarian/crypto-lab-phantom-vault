import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>');
(globalThis as unknown as { document: Document }).document = dom.window.document;

const { createDistribution } = await import('./distribution');

test('renders two histograms from real bytes and highlights the biased low positions', () => {
  const dist = createDistribution();
  // Charset size 10 → threshold floor(256/10)*10 = 250; bytes 250..255 wrap onto
  // positions 0..5, which should therefore be the highlighted (taller) bars.
  const bytes: number[] = [];
  for (let v = 0; v < 256; v += 1) {
    bytes.push(v);
  }
  dist.render(bytes, 10);

  const svgs = dist.element.querySelectorAll('.dist-svg');
  assert.equal(svgs.length, 2, 'one naive chart, one rejection chart');

  // The naive chart (first) must contain the highlighted "tall" bars; the
  // rejection chart (second) must not.
  const tallInNaive = svgs[0].querySelectorAll('.dist-bar-tall').length;
  const tallInRejection = svgs[1].querySelectorAll('.dist-bar-tall').length;
  assert.equal(tallInNaive, 6, 'six low positions get the extra wrap-around hit');
  assert.equal(tallInRejection, 0, 'rejection sampling has no favoured positions');

  const summary = dist.element.querySelector('.dist-summary')?.textContent ?? '';
  assert.match(summary, /6 low position/);
  assert.match(summary, /256 real DRBG bytes/);
});

test('empty input shows the derive-first prompt', () => {
  const dist = createDistribution();
  dist.render([], 10);
  assert.match(dist.element.textContent ?? '', /Derive a password/i);
});

test('clear() restores the empty prompt', () => {
  const dist = createDistribution();
  dist.render([1, 2, 3, 4], 10);
  dist.clear();
  assert.match(dist.element.textContent ?? '', /Derive a password/i);
});
