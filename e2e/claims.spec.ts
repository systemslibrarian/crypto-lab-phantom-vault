import { expect, test } from '@playwright/test';

test('modulo-bias panel uses exact byte-domain counts and labels run data as observation', async ({ page }) => {
  await page.goto('.');
  await page.fill('#master-passphrase', 'correct horse battery staple');
  await page.fill('#service', 'github.com');
  await page.fill('#username', 'you@example.com');
  await page.click('#derive-button');

  const summary = page.locator('.dist-summary');
  await expect(summary).toBeVisible({ timeout: 60_000 });
  await expect(summary).toContainText('Exact 256-value mapping');
  await expect(summary).toContainText('Run observation (not a statistical proof)');
  await expect(summary).not.toContainText('deviation');

  const cells = page.locator('.dist-cell');
  await expect(cells.nth(0)).toContainText(/receives \d+ of 256/);
  await expect(cells.nth(1)).toContainText(/receives exactly \d+ of \d+ accepted values/);
});
