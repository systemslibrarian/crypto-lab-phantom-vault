import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures } from './nontext';

/**
 * WCAG regression gate. Mirrors the KAT vector gate but for accessibility:
 * scans the full page with every <details> expanded and the live demo driven,
 * in both dark (default) and light themes. Also scans the "How It Works"
 * modal, which is a mutually-exclusive full-screen dialog.
 *
 * axe is not the whole oracle. Every scanned state is also measured
 * arithmetically by `./contrast` (composite-aware WCAG 1.4.3 — the gradients,
 * `color-mix()` surfaces and ancestor-opacity fades axe files under
 * `incomplete`) and by `./nontext` (WCAG 1.4.11 control boundaries and
 * generated-content ink, which axe has no rule for at all). On first wiring,
 * the pair found four defects a green axe run had been sitting on: the solid
 * action buttons and the wordlist textarea dissolving into their panels, and
 * the footer's hardcoded teal links at 1.68:1 in the light theme.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important;
      scroll-behavior:auto!important}`,
  });
}

async function openAllDetails(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of Array.from(document.querySelectorAll('details'))) {
      details.open = true;
    }
  });
}

async function mount(page: Page): Promise<void> {
  await page.goto('.');
  // The app renders synchronously in main.ts; wait for a known deep node.
  await page.locator('#derive-button').waitFor({ state: 'visible' });
  await page.locator('#cl-theme-toggle').waitFor({ state: 'visible' });
}

// Drive the live derivation so the dynamically injected DRBG state cards and
// entropy readout (async result regions) are present in the DOM when axe
// scans. PBKDF2 runs 600k iterations in a worker, so allow generous time.
async function runDemo(page: Page): Promise<void> {
  await page.fill('#master-passphrase', 'correct horse battery staple');
  await page.fill('#service', 'github.com');
  await page.fill('#username', 'you@example.com');
  await page.click('#derive-button');
  // The DRBG state cards are injected only after a successful derivation.
  await expect(page.locator('#state-list .state-item').first()).toBeVisible({
    timeout: 60_000,
  });
  await expect(page.locator('#pipeline-status')).toHaveAttribute(
    'data-state',
    'done',
  );

  // Run the offline-cracking exhibit too, so the verdict, the recovered
  // passphrase and the pivot — all injected only after a successful attack —
  // are in the DOM when axe scans. The demo passphrase is in the shipped
  // wordlist, so this exercises the recovered (worst-contrast) branch.
  await page.click('#crack-run');
  await expect(page.locator('[data-crack-verdict]')).toBeVisible({ timeout: 60_000 });
}

async function scan(page: Page, label: string, include?: string): Promise<void> {
  let builder = new AxeBuilder({ page }).withTags(TAGS);
  if (include) {
    builder = builder.include(include);
  }
  const results = await builder.analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary, `axe violations in state: ${label}`).toEqual([]);

  const contrast = await auditContrast(page);
  expect(
    formatContrastFailures(contrast),
    `measured contrast failures in state: ${label}`,
  ).toEqual([]);

  const nonText = await auditNonText(page);
  expect(
    formatNonTextFailures(nonText),
    `non-text contrast failures in state: ${label}`,
  ).toEqual([]);
}

async function scanEverything(page: Page, theme: string): Promise<void> {
  await neutralizeMotion(page);
  await openAllDetails(page);
  await runDemo(page);
  // Base page (modal closed).
  await scan(page, `${theme} / demo driven`);

  // The "How It Works" modal is a native <dialog> shown with showModal(); it
  // covers the page. Scan it open, then close so themed re-scans start clean.
  await page.click('#open-modal');
  await expect(page.locator('#how-modal')).toBeVisible();
  await scan(page, `${theme} / modal open`);
  await page.click('#close-modal');
  await expect(page.locator('#how-modal')).toBeHidden();
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await mount(page);
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await scanEverything(page, 'dark');
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await mount(page);
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await scanEverything(page, 'light');
});
