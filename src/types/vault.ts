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
}
