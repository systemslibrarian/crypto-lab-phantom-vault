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

console.log(`Sample size: ${SAMPLE_SIZE}`);
console.log(`Charset size: ${CHARSET.length}`);
console.log(`Rejected bytes: ${mapped.rejected}`);
console.log(`Chi-square: ${statistic.toFixed(2)}`);
console.log('NEEDS_VERIFICATION: compare against critical value table for df=89 based on chosen alpha.');
