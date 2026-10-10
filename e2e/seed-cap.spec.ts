import { expect, test } from '@playwright/test';

const phrase = 'A1!a'.repeat(24); // Public predictable fixture, not a strength claim.

for (const width of [1280, 380, 320]) {
  test(`long-output capacity is distinguished from reachable support and unknown entropy at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');
    await page.fill('#master-passphrase', phrase);
    await page.fill('#length', '64');
    await expect(page.locator('#cap-ceiling-value')).toContainText('414 bits');
    await expect(page.locator('#cap-effective-value')).toHaveText('256 bits');
    await expect(page.locator('#cap-verdict')).toContainText('256-bit');
    await page.click('#derive-button');
    await expect(page.locator('#pipeline-status')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    await expect(page.locator('#master-passphrase')).toHaveValue('');
    const output = await page.locator('#password-value').inputValue();
    expect(output).toHaveLength(64);
    await expect(page.locator('#entropy-effective')).toHaveText('256.0 bits');
    await expect(page.locator('#entropy-note')).toContainText('actual entropy is not measured');
    await page.fill('#crack-wordlist', phrase);
    await page.click('#crack-run');
    await expect(page.locator('[data-crack-verdict]')).toContainText('FOUND after 1 guess', { timeout: 60_000 });
    await expect(page.locator('[data-crack-recovered]')).toHaveText(phrase);
    await expect(page.locator('[data-crack-margin]')).toHaveText('256 bits');
    await expect(page.locator('[data-crack-format]')).toHaveText('414.4 bits');
    await expect(page.locator('#crack-result')).toContainText('reachable-support upper bound');
    await expect(page.locator('#crack-result')).toContainText('not a measurement of entropy');
    await expect(page.locator('#crack-result')).toContainText('Seed collisions');
    await expect(page.locator('#crack-result')).toContainText('cannot establish exact collision odds');
    await expect(page.locator('#crack-result')).not.toContainText('for every practical purpose');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  });
}
