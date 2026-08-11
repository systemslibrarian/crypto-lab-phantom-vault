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

/**
 * Derive when the expected result may be IDENTICAL to what is already on screen
 * (re-deriving the same inputs is deterministic, so `derive`'s wait-for-change
 * never fires). Blanks the readout first, then waits for the page to write a
 * value back into it. The value compared is still entirely the page's own.
 */
async function deriveAgain(page: Page, passphrase: string, service: string): Promise<string> {
  const field = page.locator('#password-value');
  await field.evaluate((el) => {
    (el as HTMLInputElement).value = '';
  });
  await expect(field).toHaveValue('');

  await page.fill('#master-passphrase', passphrase);
  await page.fill('#service', service);
  await page.fill('#username', 'you@example.com');
  await page.click('#derive-button');

  await expect(field).not.toHaveValue('', { timeout: 60_000 });
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
    'CREDENTIAL-CONSISTENT PASSPHRASE FOUND after 5 guesses',
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
  // Every one of those 8 was derived and compared — an exhaustion verdict is a
  // claim about comparisons that happened, not about candidates the pipeline
  // refused. See the cracker unit tests for the branch where that is not true.
  await expect(page.locator('[data-crack-verdict]')).toContainText(
    'every one of them derived and compared',
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
    'CREDENTIAL-CONSISTENT PASSPHRASE FOUND after 1 guess:',
  );
  await expect(page.locator('[data-crack-recovered]')).toHaveText(STRONG);
  await expect(page.locator('[data-crack-pivot]')).not.toHaveText(stolen);

  // Tie the FAILURE verdict to values the page computed, not just to its copy.
  // The credential the search exhausted against was a perfectly crackable one —
  // the miss was about the wordlist and nothing else. Prove that by having the
  // vault itself re-derive, on screen, both the credential the attack failed on
  // and the pivot the attack went on to predict once the list contained the
  // passphrase. Every value compared here was produced by the page.
  const pivotService = await page.locator('[data-crack-pivot-service]').innerText();
  const pivotPassword = await page.locator('[data-crack-pivot]').innerText();

  const reDerivedStolen = await deriveAgain(page, STRONG, 'github.com');
  expect(reDerivedStolen).toBe(stolen);

  const reDerivedPivot = await deriveAgain(page, STRONG, pivotService);
  expect(reDerivedPivot).toBe(pivotPassword);
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

/**
 * Regression — the page rated a passphrase its own attack panel then cracked.
 *
 * `Strength:` is computed from min(format ceiling, composition ceiling). Both
 * terms are ceilings, so the number can prove weakness and can never certify
 * strength. It was printed as a verdict: measured over the shipped default
 * wordlist, 5 of its 8 entries score better than Weak. This drives the exact
 * sequence a visitor takes — press the page's own "Try a weak passphrase"
 * button, derive, then run the attack — and requires the two exhibits to agree.
 */
test('the strength readout never certifies a passphrase the Break-it panel recovers', async ({
  page,
}) => {
  await page.goto('.');

  // The page's own preset: password123, length 64, every character class.
  await page.click('#cap-weak-preset');
  await expect(page.locator('#master-passphrase')).toHaveValue('password123');
  await expect(page.locator('#length')).toHaveValue('64');

  // The live cap panel must not tell the learner this passphrase is fine.
  const capVerdict = await page.locator('#cap-verdict').innerText();
  expect(capVerdict).not.toContain("is not what's holding you back");
  expect(capVerdict).not.toContain('pins effective strength');

  await page.fill('#service', 'github.com');
  await page.fill('#username', 'you@example.com');
  await page.click('#derive-button');
  await expect(page.locator('#pipeline-status')).toHaveAttribute('data-state', 'done', {
    timeout: 60_000,
  });

  // The claim: whatever band this lands in, it is stated as a ceiling unless it
  // is the one band a ceiling can prove — "Weak".
  const label = (await page.locator('#strength-label').innerText()).trim();
  const effective = Number(
    (await page.locator('#entropy-effective').innerText()).replace(' bits', '').trim(),
  );
  expect(effective, 'the readout produced a number').toBeGreaterThan(0);
  if (effective < 40) {
    expect(label).toBe('Strength: Weak');
  } else {
    expect(label, `${effective} bits printed as a verdict: ${label}`).toMatch(
      /^Strength: at most /,
    );
    const valueText = await page.locator('#strength-track').getAttribute('aria-valuetext');
    expect(valueText ?? '').toMatch(/^at most /);
  }
  // The preset exists to land above the Weak band — if it stopped doing so this
  // test would be asserting nothing, so require it.
  expect(effective, 'the weak preset still scores above the Weak band').toBeGreaterThanOrEqual(40);

  // ...and now the other exhibit, on the same page, with the same passphrase.
  await page.click('#crack-run');
  await expect(page.locator('[data-crack-verdict]')).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('[data-crack-recovered]')).toHaveText('password123');
});

/**
 * Regression — the entropy-cap panel described a passphrase the page had wiped.
 *
 * main.ts clears the passphrase field after every successful derivation via
 * form.clearSensitive(). Assigning to `input.value` fires no `input` event, so
 * the panel's listeners never ran: the dashed line, the bit count and the
 * "Capped: …" verdict stayed on screen next to an empty field, describing a
 * passphrase the page no longer held. Every derivation, every time.
 */
test('no live panel keeps describing the passphrase after the field is cleared', async ({
  page,
}) => {
  await page.goto('.');
  await page.fill('#master-passphrase', 'password123');
  await page.fill('#service', 'github.com');
  await page.fill('#username', 'you@example.com');

  // Before deriving: the panel is describing a passphrase that is really there.
  await expect(page.locator('#cap-caption')).toContainText('composition ceiling');
  expect((await page.locator('#cap-verdict').innerText()).length).toBeGreaterThan(0);

  await page.click('#derive-button');
  await expect(page.locator('#pipeline-status')).toHaveAttribute('data-state', 'done', {
    timeout: 60_000,
  });

  // The page wiped the field, so the claim is about what it now shows.
  await expect(page.locator('#master-passphrase')).toHaveValue('');
  await expect(page.locator('#cap-caption')).toContainText('Type a master passphrase above');
  await expect(page.locator('#cap-caption')).not.toContainText('composition ceiling');
  expect(
    (await page.locator('#cap-verdict').innerText()).trim(),
    'no verdict about a passphrase the page does not hold',
  ).toBe('');
  expect(
    await page.locator('#cap-line').evaluate((el) => (el as HTMLElement).style.opacity),
    'the dashed cap line is not left marking a wiped passphrase',
  ).toBe('0');

  // The derivation's own numbers stay, because they are scoped to the run that
  // produced them — this is the panel that legitimately outlives the field.
  await expect(page.locator('#entropy-passphrase')).not.toHaveText('n/a');
});
