import type { CharsetConfig } from '../types/vault';

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,./<>?';

export const CHARSETS = {
  LOWERCASE,
  UPPERCASE,
  DIGITS,
  SYMBOLS,
};

export function buildCharset(config: CharsetConfig): string {
  let charset = '';

  if (config.lowercase) {
    charset += LOWERCASE;
  }

  if (config.uppercase) {
    charset += UPPERCASE;
  }

  if (config.digits) {
    charset += DIGITS;
  }

  if (config.symbols) {
    charset += SYMBOLS;
  }

  if (charset.length === 0) {
    throw new Error('At least one character class must be selected');
  }

  return Array.from(new Set(charset)).join('');
}

export async function mapBytesToPassword(
  initialBytes: Uint8Array,
  charset: string,
  length: number,
  generateMore: () => Promise<Uint8Array>,
): Promise<{ password: string; rejectionCount: number }> {
  if (charset.length === 0) {
    throw new Error('Charset must not be empty.');
  }

  const threshold = Math.floor(256 / charset.length) * charset.length;
  const passwordChars: string[] = [];

  let rejectionCount = 0;
  let bytes = initialBytes;
  let index = 0;

  while (passwordChars.length < length) {
    if (index >= bytes.length) {
      bytes = await generateMore();
      index = 0;
      continue;
    }

    const value = bytes[index];
    index += 1;

    if (value >= threshold) {
      rejectionCount += 1;
      continue;
    }

    const charIndex = value % charset.length;
    passwordChars.push(charset[charIndex]);
  }

  return {
    password: passwordChars.join(''),
    rejectionCount,
  };
}

export function hasRequiredCharacterClasses(password: string, config: CharsetConfig): boolean {
  if (config.lowercase && !/[a-z]/.test(password)) {
    return false;
  }

  if (config.uppercase && !/[A-Z]/.test(password)) {
    return false;
  }

  if (config.digits && !/[0-9]/.test(password)) {
    return false;
  }

  if (config.symbols) {
    // Escape only the characters that are special *inside* a character class
    // (\ ] ^ -). The previous general-purpose escape left '-' unescaped, so the
    // "+-=" substring of SYMBOLS formed an unintended range ('+'..'=') that
    // swallowed digits — making digit-only passwords falsely count as having a
    // symbol. Keep '-' last so it is always treated literally.
    const escaped = SYMBOLS.replace(/[\\\]^-]/g, '\\$&');
    if (!new RegExp(`[${escaped}]`).test(password)) {
      return false;
    }
  }

  return true;
}

/**
 * Theoretical entropy of the OUTPUT FORMAT: how many bits a uniformly random
 * password of this length over this charset could hold. This is a ceiling, not
 * a promise — see estimatePassphraseEntropyBits for why.
 *
 * Uses length * log2(charsetSize) rather than log2(charsetSize ** length): the
 * two are mathematically identical, but the latter overflows to Infinity once
 * charsetSize ** length exceeds Number.MAX_VALUE.
 */
export function estimateEntropyBits(charsetSize: number, length: number): number {
  if (charsetSize <= 1 || length <= 0) {
    return 0;
  }
  return length * Math.log2(charsetSize);
}

/**
 * Rough UPPER BOUND on the entropy of the master passphrase, using the classic
 * "pool size ^ length" model. This deliberately OVERSTATES real-world phrases:
 * a dictionary word like "password" scores ~38 bits here despite being crackable
 * in milliseconds. We surface it anyway because, for a deterministic deriver, the
 * passphrase is the security floor — and showing an honest upper bound makes the
 * cap visible. The effective strength is min(this, output-format ceiling).
 */
export function estimatePassphraseEntropyBits(passphrase: string): number {
  if (!passphrase) {
    return 0;
  }

  let pool = 0;
  if (/[a-z]/.test(passphrase)) pool += 26;
  if (/[A-Z]/.test(passphrase)) pool += 26;
  if (/[0-9]/.test(passphrase)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(passphrase)) pool += 33; // printable ASCII symbols/space

  return passphrase.length * Math.log2(pool);
}

export function chiSquareUniformity(sample: string, charset: string): number {
  const expected = sample.length / charset.length;
  const observed = new Map<string, number>();

  for (const char of charset) {
    observed.set(char, 0);
  }

  for (const char of sample) {
    observed.set(char, (observed.get(char) ?? 0) + 1);
  }

  let chiSquare = 0;
  for (const char of charset) {
    const count = observed.get(char) ?? 0;
    chiSquare += ((count - expected) ** 2) / expected;
  }

  return chiSquare;
}
