export interface DistributionController {
  element: HTMLElement;
  /**
   * Render both histograms from the genuine DRBG bytes this run produced.
   * `charsetSize` is N (the character-set size the bytes were mapped onto).
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
 * Count how each real byte lands under two mapping strategies.
 *  - naive:     value % N for EVERY byte (this is what introduces modulo bias)
 *  - rejection: value % N only for bytes below floor(256/N)*N; the rest are
 *               counted as rejected (this is what the pipeline actually does)
 */
function tallies(
  bytes: number[],
  n: number,
): { naive: number[]; rejection: number[]; rejected: number } {
  const naive = new Array<number>(n).fill(0);
  const rejection = new Array<number>(n).fill(0);
  const threshold = Math.floor(256 / n) * n;
  let rejected = 0;

  for (const value of bytes) {
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
      Both charts below are built from the <strong>same real DRBG bytes this run produced</strong>,
      binned by which character position they land on. The naive
      <code>byte % N</code> map (left) leans on the low positions, because 256 rarely divides
      evenly by <em>N</em>. Rejection sampling (right) throws away the few bytes in the uneven
      tail, leaving a flat, unbiased distribution — the same map this demo actually uses.
    </p>

    <div class="dist-grid" id="dist-grid">
      <p class="helper-text dist-empty" id="dist-empty">Derive a password to plot this run's byte distribution.</p>
    </div>
  `;

  const grid = requireNode<HTMLElement>(wrapper, '#dist-grid');

  function render(sampledBytes: number[], charsetSize: number): void {
    const n = charsetSize;
    if (!Number.isFinite(n) || n < 2 || sampledBytes.length === 0) {
      clear();
      return;
    }

    const { naive, rejection, rejected } = tallies(sampledBytes, n);
    const threshold = Math.floor(256 / n) * n;
    // Positions that receive an EXTRA hit from wrap-around are the biased ones:
    // values [threshold, 256) land on positions [0, 256 - threshold).
    const extraHitCount = 256 - threshold; // number of low positions favoured
    const biasedIndices = new Set<number>();
    for (let i = 0; i < extraHitCount; i += 1) {
      biasedIndices.add(i);
    }

    const max = Math.max(1, ...naive, ...rejection);
    const total = sampledBytes.length;

    // Chi-square-style spread readout so a professional reader gets a number,
    // not just a picture: mean absolute deviation from the flat expectation.
    const expNaive = total / n;
    const madNaive =
      naive.reduce((sum, c) => sum + Math.abs(c - expNaive), 0) / n;
    const accepted = total - rejected;
    const expRej = accepted / n;
    const madRej =
      rejection.reduce((sum, c) => sum + Math.abs(c - expRej), 0) / n;

    grid.innerHTML = `
      <figure class="dist-cell">
        <figcaption class="dist-cap dist-cap-biased">Naive <code>byte % ${n}</code> — biased</figcaption>
        ${buildChart(naive, max, biasedIndices)}
        <p class="dist-note">
          Low positions (highlighted) get an extra hit each. Mean deviation from flat:
          <strong>${madNaive.toFixed(1)}</strong>.
        </p>
      </figure>
      <figure class="dist-cell">
        <figcaption class="dist-cap dist-cap-flat">Rejection sampling — uniform</figcaption>
        ${buildChart(rejection, max, new Set())}
        <p class="dist-note">
          ${rejected} of ${total} bytes rejected. Mean deviation from flat:
          <strong>${madRej.toFixed(1)}</strong>.
        </p>
      </figure>
      <p class="dist-summary" role="status" aria-live="polite">
        From ${total} real DRBG bytes over an ${n}-character set (reject at ≥ ${threshold}):
        the naive map favours ${extraHitCount} low position${extraHitCount === 1 ? '' : 's'}
        (deviation ${madNaive.toFixed(1)}); rejection sampling flattens it (deviation ${madRej.toFixed(1)}).
      </p>
    `;
  }

  function clear(): void {
    grid.innerHTML =
      '<p class="helper-text dist-empty" id="dist-empty">Derive a password to plot this run\'s byte distribution.</p>';
  }

  return {
    element: wrapper,
    render,
    clear,
  };
}
