export type KeyType = 'curve25519' | 'x25519' | 'ed25519' | string;

export type KeyPair = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  keyType: KeyType;
};

export type StringKeyPair = {
  publicKey: string;
  privateKey: string;
  keyType: KeyType;
};

export type CryptoBox = {
  ciphertext: Uint8Array;
  mac: Uint8Array;
};

export type StringCryptoBox = {
  ciphertext: string;
  mac: string;
};

export type SecretBox = {
  cipher: Uint8Array;
  mac: Uint8Array;
};

export type StringSecretBox = {
  cipher: string;
  mac: string;
};

export type CryptoKX = {
  sharedRx: Uint8Array;
  sharedTx: Uint8Array;
};

export type StringCryptoKX = {
  sharedRx: string;
  sharedTx: string;
};

export type MessageTag = {
  message: Uint8Array;
  tag: number;
};

export type StringMessageTag = {
  message: string;
  tag: number;
};
