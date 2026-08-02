export interface DistributionController {
  element: HTMLElement;
  /**
   * Render the exact mapping frequencies over the complete 256-byte input
   * domain. `sampledBytes` is used only for an explicitly labelled run note.
   */
  render: (sampledBytes: number[], charsetSize: number) => void;
  clear: () => void;
}

function requireNode<T extends Element>(parent: ParentNode, selector: string): T {
  const node = parent.querySelector<T>(selector);
  if (!node) {
    throw new Error(`Missing distribution node: ${selector}`);
  }
  return node;
}

/**
 * Count how every possible byte lands under two mapping strategies.
 *  - naive:     value % N for EVERY byte (this is what introduces modulo bias)
 *  - rejection: value % N only for bytes below floor(256/N)*N; the rest are
 *               counted as rejected (this is what the pipeline actually does)
 */
function tallies(
  n: number,
): { naive: number[]; rejection: number[]; rejected: number } {
  const naive = new Array<number>(n).fill(0);
  const rejection = new Array<number>(n).fill(0);
  const threshold = Math.floor(256 / n) * n;
  let rejected = 0;

  for (let value = 0; value < 256; value += 1) {
    naive[value % n] += 1;
    if (value >= threshold) {
      rejected += 1;
    } else {
      rejection[value % n] += 1;
    }
  }

  return { naive, rejection, rejected };
}

// SVG bar-chart builder. Height is fixed; bar heights scale to the max count
// seen across BOTH charts so the naive skew is visible against the flat one.
function buildChart(counts: number[], max: number, biasedIndices: Set<number>): string {
  const width = 100;
  const height = 40;
  const n = counts.length;
  const barW = width / n;
  const bars = counts
    .map((count, i) => {
      const h = max > 0 ? (count / max) * height : 0;
      const y = height - h;
      const x = i * barW;
      const cls = biasedIndices.has(i) ? 'dist-bar dist-bar-tall' : 'dist-bar';
      return `<rect class="${cls}" x="${x.toFixed(3)}" y="${y.toFixed(3)}" width="${(barW * 0.82).toFixed(3)}" height="${Math.max(0, h).toFixed(3)}" />`;
    })
    .join('');
  return `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-hidden="true" class="dist-svg">${bars}</svg>`;
}

export function createDistribution(): DistributionController {
  const wrapper = document.createElement('section');
  wrapper.className = 'panel';

  wrapper.innerHTML = `
    <h2 class="panel-title">Seeing modulo bias — and watching it vanish</h2>
    <p class="helper-text">
      Both charts enumerate all <strong>256 possible byte values</strong>, binned by which
      character position they land on. Their shape is exact rather than an inference
      from this run's small random sample. The naive <code>byte % N</code> map (left) favours
      low positions whenever 256 does not divide evenly by <em>N</em>. Rejection sampling
      (right) discards the uneven tail, giving every position the same number of inputs.
    </p>

    <div class="dist-grid" id="dist-grid">
      <p class="helper-text dist-empty" id="dist-empty">Derive a password to reveal the exact mapping comparison and this run's observation.</p>
    </div>
  `;

  const grid = requireNode<HTMLElement>(wrapper, '#dist-grid');

  function render(sampledBytes: number[], charsetSize: number): void {
    const n = charsetSize;
    if (!Number.isFinite(n) || n < 2 || sampledBytes.length === 0) {
      clear();
      return;
    }

    const { naive, rejection, rejected } = tallies(n);
    const threshold = Math.floor(256 / n) * n;
    // Positions that receive an EXTRA hit from wrap-around are the biased ones:
    // values [threshold, 256) land on positions [0, 256 - threshold).
    const extraHitCount = 256 - threshold; // number of low positions favoured
    const biasedIndices = new Set<number>();
    for (let i = 0; i < extraHitCount; i += 1) {
      biasedIndices.add(i);
    }

    const max = Math.max(1, ...naive, ...rejection);
    const baseHits = Math.floor(256 / n);
    const favoredHits = baseHits + 1;
    const observedRejected = sampledBytes.filter((value) => value >= threshold).length;

    grid.innerHTML = `
      <figure class="dist-cell">
        <figcaption class="dist-cap dist-cap-biased">Naive <code>byte % ${n}</code> — biased</figcaption>
        ${buildChart(naive, max, biasedIndices)}
        <p class="dist-note">
          Each highlighted low position receives <strong>${favoredHits} of 256</strong>
          possible byte values; every other position receives ${baseHits}.
        </p>
      </figure>
      <figure class="dist-cell">
        <figcaption class="dist-cap dist-cap-flat">Rejection sampling — uniform</figcaption>
        ${buildChart(rejection, max, new Set())}
        <p class="dist-note">
          Reject byte values ${threshold}–255 (${rejected} values). Each position then
          receives exactly <strong>${baseHits} of ${threshold}</strong> accepted values.
        </p>
      </figure>
      <p class="dist-summary" role="status" aria-live="polite">
        Exact 256-value mapping for an ${n}-character set: the naive map favours
        ${extraHitCount} low position${extraHitCount === 1 ? '' : 's'}; rejection sampling
        gives every position ${baseHits} inputs. Run observation (not a statistical proof):
        ${observedRejected} of this run's ${sampledBytes.length} generated bytes fell in the rejected tail.
      </p>
    `;
  }

  function clear(): void {
    grid.innerHTML =
      '<p class="helper-text dist-empty" id="dist-empty">Derive a password to reveal the exact mapping comparison and this run\'s observation.</p>';
  }

  return {
    element: wrapper,
    render,
    clear,
  };
}
