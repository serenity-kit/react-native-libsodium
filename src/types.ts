export enum base64_variants {
  ORIGINAL = 1,
  ORIGINAL_NO_PADDING = 3,
  URLSAFE = 5,
  URLSAFE_NO_PADDING = 7,
}

export type Uint8ArrayOutputFormat = 'uint8array';

export type StringOutputFormat = 'text' | 'hex' | 'base64';

export type OutputFormat =
  | StringOutputFormat
  | Uint8ArrayOutputFormat
  | null
  | undefined;

export type KeyType = 'curve25519' | 'ed25519' | 'x25519';

export interface KeyPair {
  keyType: KeyType;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface StringKeyPair {
  keyType: KeyType;
  privateKey: string;
  publicKey: string;
}
