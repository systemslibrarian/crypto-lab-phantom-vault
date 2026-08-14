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
 *
 * Motion is suppressed by EMULATING the reduced-motion preference, never by
 * injecting styles: an earlier `addStyleTag` injection replaced the page's own
 * `@media (prefers-reduced-motion: reduce)` block instead of exercising it, so
 * the rendering that a reader with the preference set actually gets was never
 * the one scanned — and an animation whose end state that block failed to
 * restore would have been structurally invisible. See `expectNotBlank`.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Wait for every running animation and transition to drain before a scan.
 *
 * Under the reduced motion this suite emulates, `style.css`'s
 * `* { animation: none !important; transition: none !important }` block means
 * `getAnimations()` is normally empty and this returns on the sixth quiet
 * frame. It stays load-bearing anyway: if that block ever stops covering a
 * new animation, a scan sampling it mid-flight would report a colour that
 * exists in no settled state of the page. Six consecutive quiet frames rather
 * than one, because transitions drain in waves; infinite animations are
 * excluded rather than waited on, and a wall-clock budget bounds the rest.
 */
async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        // An infinite decorative animation never drains; waiting on it hangs.
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' },
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. The old
 * `addStyleTag` injection could never see this class: it replaced the page's
 * own reduced-motion block instead of exercising it.
 *
 * `style.css` cannot currently be in that shape — its two `@keyframes`
 * (`status-pulse`, box-shadow only; `ratchet-in`, ending at base-state values)
 * both leave the base rendering visible when cancelled — but that is a property
 * of the current stylesheet, so the check runs in every scanned state anyway.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

async function openAllDetails(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of Array.from(document.querySelectorAll('details'))) {
      details.open = true;
    }
  });
}

async function mount(page: Page): Promise<void> {
  // The reduced-motion preference is set through emulation, not injection, so
  // the page's OWN `@media (prefers-reduced-motion: reduce)` block is what the
  // suite exercises. `test.use({ reducedMotion: 'reduce' })` silently does
  // nothing on Playwright 1.61.1, so the emulation is applied imperatively
  // before the navigation and then asserted from inside the page — if it ever
  // silently failed, the suite would scan the animated rendering while
  // claiming to scan the reduced-motion one.
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect',
  ).toBe(true);
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
  await settle(page);
  await expectNotBlank(page, label);
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
