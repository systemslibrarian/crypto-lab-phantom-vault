export interface VaultInputs {
  masterPassphrase: string;
  service: string;
  username: string;
  version: number;
  length: number;
  charset: CharsetConfig;
}

export interface CharsetConfig {
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
}

export interface DRBGState {
  K: string;
  V: string;
  reseedCounter: number;
}

export interface DerivationResult {
  password: string;
  drbgStates: DRBGState[];
  pbkdf2Iterations: number;
  bytesGenerated: number;
  rejectionCount: number;
  /**
   * The raw DRBG byte values (0–255) actually produced during this run's
   * character mapping, in order. Kept so the distribution exhibit can plot the
   * genuine bytes rather than a fabricated histogram.
   *
   * Treat these as secret-equivalent derived material — an earlier comment
   * here called them "not a secret", which was simply false: every accepted
   * byte maps one-to-one onto a character of the derived password
   * (`value % charset.length`), so anyone holding this array can reconstruct
   * the password. They exist only inside this run's result object, the
   * exhibit renders aggregate counts rather than the sequence, and the run's
   * results are retired when its inputs change.
   */
  sampledBytes: number[];
}
