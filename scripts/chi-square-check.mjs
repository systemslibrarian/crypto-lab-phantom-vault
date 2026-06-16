const CHARSET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,./<>?';
const SAMPLE_SIZE = 100000;

function mapBytesToChars(bytes, charset) {
  const threshold = Math.floor(256 / charset.length) * charset.length;
  const out = [];
  let rejected = 0;

  for (const byte of bytes) {
    if (out.length >= SAMPLE_SIZE) {
      break;
    }

    if (byte >= threshold) {
      rejected += 1;
      continue;
    }

    out.push(charset[byte % charset.length]);
  }

  return { sample: out.join(''), rejected };
}

function chiSquare(sample, charset) {
  const expected = sample.length / charset.length;
  const counts = new Map([...charset].map((char) => [char, 0]));

  for (const char of sample) {
    counts.set(char, counts.get(char) + 1);
  }

  let chi = 0;
  for (const char of charset) {
    const observed = counts.get(char);
    chi += ((observed - expected) ** 2) / expected;
  }

  return chi;
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  const chunkSize = 65536;

  for (let offset = 0; offset < length; offset += chunkSize) {
    const size = Math.min(chunkSize, length - offset);
    const chunk = crypto.getRandomValues(new Uint8Array(size));
    bytes.set(chunk, offset);
  }

  return bytes;
}

let source = randomBytes(SAMPLE_SIZE * 3);
let mapped = mapBytesToChars(source, CHARSET);

while (mapped.sample.length < SAMPLE_SIZE) {
  const more = randomBytes(SAMPLE_SIZE);
  const additional = mapBytesToChars(more, CHARSET);
  mapped = {
    sample: mapped.sample + additional.sample,
    rejected: mapped.rejected + additional.rejected,
  };
}

mapped.sample = mapped.sample.slice(0, SAMPLE_SIZE);
const statistic = chiSquare(mapped.sample, CHARSET);

/**
 * Upper-tail chi-square critical value via the Wilson–Hilferty approximation.
 * Accurate to well under 1% for the degrees of freedom we use here (df = 88),
 * which keeps this script dependency-free. z is the standard-normal quantile
 * for the chosen upper-tail alpha.
 */
function chiSquareCritical(df, z) {
  const term = 1 - 2 / (9 * df) + z * Math.sqrt(2 / (9 * df));
  return df * term ** 3;
}

const df = CHARSET.length - 1;
// Strict alpha: a correct uniform mapping sits near df (=88), so it clears this
// bar ~99.99% of the time — safe to gate CI on. A biased mapping (e.g. naive
// `byte % N`) inflates the statistic into the hundreds or thousands, far past
// this threshold, so genuine bias is still caught deterministically.
const ALPHA = 1e-4;
const Z_ALPHA = 3.719016485; // standard-normal upper-tail quantile for 1e-4
const critical = chiSquareCritical(df, Z_ALPHA);
const pass = statistic < critical;

console.log(`Sample size:    ${SAMPLE_SIZE}`);
console.log(`Charset size:   ${CHARSET.length}`);
console.log(`Rejected bytes: ${mapped.rejected}`);
console.log(`Degrees of freedom (df): ${df}`);
console.log(`Chi-square statistic:    ${statistic.toFixed(2)}`);
console.log(`Critical value (alpha=${ALPHA}): ${critical.toFixed(2)}`);
console.log('');
console.log(
  pass
    ? `PASS: ${statistic.toFixed(2)} < ${critical.toFixed(2)} — distribution is consistent with uniform (fail to reject H0). Rejection sampling removed modulo bias as intended.`
    : `FAIL: ${statistic.toFixed(2)} >= ${critical.toFixed(2)} — distribution deviates from uniform at alpha=${ALPHA}. Investigate the mapping.`,
);

// Non-zero exit on failure so this can gate CI if wired up.
process.exitCode = pass ? 0 : 1;
