import { expect, test, type Page } from '@playwright/test';

const STRONG = 'zq7-tessellate-marmoset-9x';

/** Fill the form and derive, returning the password the page computed. */
async function derive(page: Page, passphrase: string, service: string): Promise<string> {
  const field = page.locator('#password-value');
  const before = await field.inputValue().catch(() => '');
  await page.fill('#master-passphrase', passphrase);
  await page.fill('#service', service);
  await page.fill('#username', 'you@example.com');
  await page.click('#derive-button');
  await expect(field).not.toHaveValue(before, { timeout: 60_000 });
  await expect(page.locator('#pipeline-status')).toHaveAttribute('data-state', 'done');
  const password = await field.inputValue();
  expect(password).toHaveLength(20);
  return password;
}

async function runAttack(page: Page): Promise<void> {
  await page.click('#crack-run');
  await expect(page.locator('[data-crack-verdict]')).toBeVisible({ timeout: 60_000 });
}

test('break-it panel recovers a weak passphrase and its pivot matches what the vault itself derives', async ({
  page,
}) => {
  await page.goto('.');
  const stolen = await derive(page, 'password123', 'github.com');

  // The panel's own claim: it is armed with the derived password, never the
  // passphrase. The form field must be empty before the search even starts.
  await expect(page.locator('#master-passphrase')).toHaveValue('');
  await expect(page.locator('#crack-armed')).toContainText('Not the passphrase.');

  await runAttack(page);

  // "password123" is the 5th entry of the shipped wordlist, so a genuine
  // sequential search must report exactly 5 guesses — a hardcoded verdict or a
  // short-circuit would not land on that number.
  await expect(page.locator('[data-crack-verdict]')).toContainText(
    'MASTER PASSPHRASE RECOVERED after 5 guesses',
  );
  await expect(page.locator('[data-crack-recovered]')).toHaveText('password123');

  const pivotService = await page.locator('[data-crack-pivot-service]').innerText();
  const pivotPassword = await page.locator('[data-crack-pivot]').innerText();
  expect(pivotService).not.toBe('github.com');
  expect(pivotPassword).not.toBe(stolen);

  // The load-bearing assertion: the attack panel's prediction for a service it
  // never derived on-screen is checked against the vault's own deriver. Both
  // values come from the page; neither is written into this test.
  const vaultDerived = await derive(page, 'password123', pivotService);
  expect(vaultDerived).toBe(pivotPassword);
});

test('break-it panel genuinely fails outside the wordlist, and the same credential falls once the list contains it', async ({
  page,
}) => {
  await page.goto('.');
  const stolen = await derive(page, STRONG, 'github.com');

  await runAttack(page);

  // Failure path: the whole 8-entry list ran and produced nothing.
  await expect(page.locator('[data-crack-verdict]')).toContainText(
    'NOT RECOVERED — the wordlist was exhausted after 8 guesses',
  );
  await expect(page.locator('#crack-status')).toContainText(
    'Master passphrase not recovered.',
  );
  await expect(page.locator('[data-crack-recovered]')).toHaveCount(0);
  await expect(page.locator('[data-crack-pivot]')).toHaveCount(0);

  // Same stolen credential, same page, only the attacker's wordlist changed:
  // the verdict must flip. That is what makes the failure above meaningful —
  // the panel can fail, and it failed for the right reason.
  await page.fill('#crack-wordlist', STRONG);
  await runAttack(page);
  await expect(page.locator('[data-crack-verdict]')).toContainText(
    'MASTER PASSPHRASE RECOVERED after 1 guess:',
  );
  await expect(page.locator('[data-crack-recovered]')).toHaveText(STRONG);
  await expect(page.locator('[data-crack-pivot]')).not.toHaveText(stolen);
});

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
