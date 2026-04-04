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
    const symbols = config.customSymbols?.length ? config.customSymbols : SYMBOLS;
    if (/\s|[\x00-\x1F\x7F]/.test(symbols)) {
      throw new Error('Custom symbols cannot include whitespace or control characters.');
    }
    charset += symbols;
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
    const symbols = config.customSymbols?.length ? config.customSymbols : SYMBOLS;
    const escaped = symbols.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (!new RegExp(`[${escaped}]`).test(password)) {
      return false;
    }
  }

  return true;
}

export function estimateEntropyBits(charsetSize: number, length: number): number {
  return Math.log2(charsetSize ** length);
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
