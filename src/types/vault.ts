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
   * genuine bytes rather than a fabricated histogram. Not a secret: these are
   * pre-mapping generator outputs, not the derived password.
   */
  sampledBytes: number[];
}
