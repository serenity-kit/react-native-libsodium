export { base64_variants, to_string } from './libsodium-js-utils';
import type { KeyPair, StringKeyPair } from './libsodium-types';
import type {
  StringOutputFormat,
  Uint8ArrayOutputFormat,
} from 'libsodium-wrappers';
import { base64_variants, to_string } from './libsodium-js-utils';
import type { OutputFormat } from './types';
import { convertToOutputFormat } from './utils';

import { NativeModules } from 'react-native';

const toArrayBuffer = (input: Uint8Array): ArrayBuffer => {
  const buffer = input.buffer;
  if (
    buffer instanceof ArrayBuffer &&
    input.byteOffset === 0 &&
    input.byteLength === buffer.byteLength
  ) {
    return buffer;
  }
  return input.slice().buffer;
};

const Libsodium = NativeModules.Libsodium;

if (Libsodium && typeof Libsodium.install === 'function') {
  console.log('calling Libsodium.install');
  Libsodium.install();
} else if (!Libsodium) {
  console.warn('Libsodium module not defined');
} else {
  console.warn('Libsodium.install not a function');
}

declare global {
  var jsi_crypto_auth_BYTES: number;
  var jsi_crypto_auth_KEYBYTES: number;
  var jsi_crypto_secretbox_KEYBYTES: number;
  var jsi_crypto_secretbox_NONCEBYTES: number;
  var jsi_crypto_box_PUBLICKEYBYTES: number;
  var jsi_crypto_box_SECRETKEYBYTES: number;
  var jsi_crypto_box_NONCEBYTES: number;
  var jsi_crypto_box_SEEDBYTES: number;
  var jsi_crypto_aead_xchacha20poly1305_ietf_KEYBYTES: number;
  var jsi_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: number;
  var jsi_crypto_kdf_KEYBYTES: number;
  var jsi_crypto_kdf_CONTEXTBYTES: number;
  var jsi_crypto_generichash_BYTES: number;
  var jsi_crypto_generichash_BYTES_MIN: number;
  var jsi_crypto_generichash_BYTES_MAX: number;
  var jsi_crypto_generichash_KEYBYTES: number;
  var jsi_crypto_generichash_KEYBYTES_MIN: number;
  var jsi_crypto_generichash_KEYBYTES_MAX: number;
  var jsi_crypto_sign_SEEDBYTES: number;
  var jsi_crypto_pwhash_SALTBYTES: number;
  var jsi_crypto_pwhash_ALG_DEFAULT: number;
  var jsi_crypto_pwhash_OPSLIMIT_INTERACTIVE: number;
  var jsi_crypto_pwhash_MEMLIMIT_INTERACTIVE: number;
  var jsi_crypto_pwhash_BYTES_MIN: number;
  var jsi_crypto_pwhash_BYTES_MAX: number;
  var jsi_crypto_kdf_hkdf_sha256_BYTES_MAX: number;
  var jsi_crypto_kdf_hkdf_sha256_BYTES_MIN: number;
  var jsi_crypto_kdf_hkdf_sha256_KEYBYTES: number;
  var jsi_crypto_pwhash_ALG_ARGON2ID13: number;

  function jsi_crypto_auth(
    message: string | ArrayBuffer,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_auth_verify(
    tag: ArrayBuffer,
    message: string | ArrayBuffer,
    key: ArrayBuffer
  ): boolean;
  function jsi_crypto_auth_keygen(): ArrayBuffer;
  function jsi_from_base64_to_arraybuffer(
    input: string,
    variant?: base64_variants
  ): ArrayBuffer;
  function jsi_to_base64(
    input: string | ArrayBuffer,
    variant: base64_variants
  ): string;
  function jsi_to_hex(input: string | ArrayBuffer): string;
  function jsi_randombytes_buf(length: number): ArrayBuffer;
  function jsi_randombytes_uniform(upper_bound: number): number;
  function jsi_crypto_secretbox_keygen(): ArrayBuffer;
  function jsi_crypto_aead_xchacha20poly1305_ietf_keygen(): ArrayBuffer;
  function jsi_crypto_kdf_keygen(): ArrayBuffer;
  function jsi_crypto_box_keypair(): {
    publicKey: ArrayBuffer;
    secretKey: ArrayBuffer;
  };
  function jsi_crypto_box_seed_keypair(seed: ArrayBuffer): {
    publicKey: ArrayBuffer;
    secretKey: ArrayBuffer;
  };
  function jsi_crypto_sign_keypair(): {
    publicKey: ArrayBuffer;
    secretKey: ArrayBuffer;
  };
  function jsi_crypto_sign_seed_keypair(seed: ArrayBuffer): {
    publicKey: ArrayBuffer;
    secretKey: ArrayBuffer;
  };
  function jsi_crypto_sign_detached(
    message: string | ArrayBuffer,
    privateKey: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_sign_verify_detached(
    signature: ArrayBuffer,
    message: string | ArrayBuffer,
    publicKey: ArrayBuffer
  ): boolean;
  function jsi_crypto_secretbox_easy(
    message: string | ArrayBuffer,
    nonce: ArrayBuffer,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_secretbox_open_easy(
    ciphertext: string | ArrayBuffer,
    nonce: ArrayBuffer,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_box_easy(
    message: string | ArrayBuffer,
    nonce: ArrayBuffer,
    publicKey: ArrayBuffer,
    secretKey: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_box_open_easy(
    ciphertext: string | ArrayBuffer,
    nonce: ArrayBuffer,
    publicKey: ArrayBuffer,
    secretKey: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_box_seal(
    message: string | ArrayBuffer,
    publicKey: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_box_seal_open(
    ciphertext: string | ArrayBuffer,
    publicKey: ArrayBuffer,
    secretKey: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_generichash(
    hashLength: number,
    message: string | ArrayBuffer,
    key?: ArrayBuffer | null | undefined
  ): ArrayBuffer;
  function jsi_crypto_pwhash(
    keyLength: number,
    password: string | ArrayBuffer,
    salt: ArrayBuffer,
    opsLimit: number,
    memLimit: number,
    algorithm: number
  ): ArrayBuffer;
  function jsi_crypto_sign_ed25519_pk_to_curve25519(
    publicKey: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_kdf_derive_from_key(
    subkeyLength: number,
    subkeyId: number,
    context: string,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_aead_xchacha20poly1305_ietf_encrypt(
    message: string | ArrayBuffer,
    additionalData: string,
    public_nonce: ArrayBuffer,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_aead_xchacha20poly1305_ietf_decrypt(
    ciphertext: string | ArrayBuffer,
    additionalData: string,
    public_nonce: ArrayBuffer,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_aead_xchacha20poly1305_ietf_decrypt(
    ciphertext: string | ArrayBuffer,
    additionalData: string,
    public_nonce: ArrayBuffer,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_kdf_hkdf_sha256_extract(
    key: ArrayBuffer,
    salt: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_kdf_hkdf_sha256_expand(
    key: ArrayBuffer,
    info: string,
    length: number
  ): ArrayBuffer;
}

export const crypto_auth_BYTES = global.jsi_crypto_auth_BYTES;
export const crypto_auth_KEYBYTES = global.jsi_crypto_auth_KEYBYTES;
export const crypto_secretbox_KEYBYTES = global.jsi_crypto_secretbox_KEYBYTES;
export const crypto_secretbox_NONCEBYTES =
  global.jsi_crypto_secretbox_NONCEBYTES;
export const crypto_box_PUBLICKEYBYTES = global.jsi_crypto_box_PUBLICKEYBYTES;
export const crypto_box_SECRETKEYBYTES = global.jsi_crypto_box_SECRETKEYBYTES;
export const crypto_box_NONCEBYTES = global.jsi_crypto_box_NONCEBYTES;
export const crypto_box_SEEDBYTES = global.jsi_crypto_box_SEEDBYTES;
export const crypto_aead_xchacha20poly1305_ietf_KEYBYTES =
  global.jsi_crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
export const crypto_aead_xchacha20poly1305_ietf_NPUBBYTES =
  global.jsi_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
export const crypto_kdf_KEYBYTES = global.jsi_crypto_kdf_KEYBYTES;
export const crypto_kdf_CONTEXTBYTES = global.jsi_crypto_kdf_CONTEXTBYTES;
export const crypto_generichash_BYTES = global.jsi_crypto_generichash_BYTES;
export const crypto_generichash_BYTES_MIN =
  global.jsi_crypto_generichash_BYTES_MIN;
export const crypto_generichash_BYTES_MAX =
  global.jsi_crypto_generichash_BYTES_MAX;
export const crypto_generichash_KEYBYTES =
  global.jsi_crypto_generichash_KEYBYTES;
export const crypto_generichash_KEYBYTES_MIN =
  global.jsi_crypto_generichash_KEYBYTES_MIN;
export const crypto_generichash_KEYBYTES_MAX =
  global.jsi_crypto_generichash_KEYBYTES_MAX;
export const crypto_sign_SEEDBYTES = global.jsi_crypto_sign_SEEDBYTES;
export const crypto_pwhash_SALTBYTES = global.jsi_crypto_pwhash_SALTBYTES;
export const crypto_pwhash_ALG_DEFAULT = global.jsi_crypto_pwhash_ALG_DEFAULT;
export const crypto_pwhash_OPSLIMIT_INTERACTIVE =
  global.jsi_crypto_pwhash_OPSLIMIT_INTERACTIVE;
export const crypto_pwhash_MEMLIMIT_INTERACTIVE =
  global.jsi_crypto_pwhash_MEMLIMIT_INTERACTIVE;
export const crypto_pwhash_BYTES_MIN = global.jsi_crypto_pwhash_BYTES_MIN;
export const crypto_pwhash_BYTES_MAX = global.jsi_crypto_pwhash_BYTES_MAX;
export const _unstable_crypto_kdf_hkdf_sha256_BYTES_MAX =
  global.jsi_crypto_kdf_hkdf_sha256_BYTES_MAX;
export const _unstable_crypto_kdf_hkdf_sha256_BYTES_MIN =
  global.jsi_crypto_kdf_hkdf_sha256_BYTES_MIN;
export const _unstable_crypto_kdf_hkdf_sha256_KEYBYTES =
  global.jsi_crypto_kdf_hkdf_sha256_KEYBYTES;
export const crypto_pwhash_ALG_ARGON2ID13 =
  global.jsi_crypto_pwhash_ALG_ARGON2ID13;

export const from_base64 = (
  input: string,
  variant?: base64_variants
): Uint8Array => {
  const variantToUse = variant || base64_variants.URLSAFE_NO_PADDING;
  const result = global.jsi_from_base64_to_arraybuffer(input, variantToUse);
  return new Uint8Array(result);
};

export const to_base64 = (
  input: string | Uint8Array,
  variant?: base64_variants
): string => {
  const variantToUse = variant || base64_variants.URLSAFE_NO_PADDING;
  const inputParam = typeof input === 'string' ? input : toArrayBuffer(input);
  return global.jsi_to_base64(inputParam, variantToUse);
};

export function to_hex(input: string | Uint8Array): string {
  const inputParam = typeof input === 'string' ? input : toArrayBuffer(input);
  return global.jsi_to_hex(inputParam);
}

export function memzero(bytes: Uint8Array): void {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('Only Uint8Array instances can be wiped');
  }
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = 0;
  }
}

export function randombytes_buf(
  length: number,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function randombytes_buf(
  length: number,
  outputFormat: StringOutputFormat
): string;
export function randombytes_buf(
  length: number,
  outputFormat?: OutputFormat | null
): unknown {
  const result = global.jsi_randombytes_buf(length);
  return convertToOutputFormat(result, outputFormat);
}

export function randombytes_uniform(upper_bound: number): number {
  return global.jsi_randombytes_uniform(upper_bound);
}

export function crypto_auth(
  message: string | Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_auth(
  message: string | Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat
): string;
export function crypto_auth(
  message: string | Uint8Array,
  key: Uint8Array,
  outputFormat: OutputFormat
): unknown {
  const messageParam =
    typeof message === 'string' ? message : toArrayBuffer(message);
  const result = global.jsi_crypto_auth(messageParam, toArrayBuffer(key));
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_auth_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_auth_keygen(outputFormat: StringOutputFormat): string;
export function crypto_auth_keygen(outputFormat: OutputFormat): unknown {
  const result = global.jsi_crypto_auth_keygen();
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_auth_verify(
  tag: Uint8Array,
  message: string | Uint8Array,
  key: Uint8Array
): boolean {
  const messageParam =
    typeof message === 'string' ? message : toArrayBuffer(message);
  return global.jsi_crypto_auth_verify(
    toArrayBuffer(tag),
    messageParam,
    toArrayBuffer(key)
  );
}

export function crypto_secretbox_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_secretbox_keygen(
  outputFormat: StringOutputFormat
): string;
export function crypto_secretbox_keygen(outputFormat: OutputFormat): unknown {
  const result = global.jsi_crypto_secretbox_keygen();
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_aead_xchacha20poly1305_ietf_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_aead_xchacha20poly1305_ietf_keygen(
  outputFormat: StringOutputFormat
): string;
export function crypto_aead_xchacha20poly1305_ietf_keygen(
  outputFormat: OutputFormat
): unknown {
  const result = global.jsi_crypto_aead_xchacha20poly1305_ietf_keygen();
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_kdf_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_kdf_keygen(outputFormat: StringOutputFormat): string;
export function crypto_kdf_keygen(outputFormat: OutputFormat): unknown {
  const result = global.jsi_crypto_kdf_keygen();
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_box_keypair(
  outputFormat?: Uint8ArrayOutputFormat | null
): KeyPair;
export function crypto_box_keypair(
  outputFormat: StringOutputFormat
): StringKeyPair;
export function crypto_box_keypair(outputFormat: OutputFormat): unknown {
  const result = global.jsi_crypto_box_keypair();
  return {
    keyType: 'x25519',
    publicKey: convertToOutputFormat(result.publicKey, outputFormat),
    privateKey: convertToOutputFormat(result.secretKey, outputFormat),
  };
}

export function crypto_box_seed_keypair(
  seed: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): KeyPair;
export function crypto_box_seed_keypair(
  seed: Uint8Array,
  outputFormat: StringOutputFormat
): StringKeyPair;
export function crypto_box_seed_keypair(
  seed: Uint8Array,
  outputFormat: OutputFormat
): unknown {
  const result = global.jsi_crypto_box_seed_keypair(toArrayBuffer(seed));
  return {
    keyType: 'x25519',
    publicKey: convertToOutputFormat(result.publicKey, outputFormat),
    privateKey: convertToOutputFormat(result.secretKey, outputFormat),
  };
}

export function crypto_sign_keypair(
  outputFormat?: Uint8ArrayOutputFormat | null
): KeyPair;
export function crypto_sign_keypair(
  outputFormat: StringOutputFormat
): StringKeyPair;
export function crypto_sign_keypair(outputFormat: OutputFormat): unknown {
  const result = global.jsi_crypto_sign_keypair();
  return {
    keyType: 'ed25519',
    publicKey: convertToOutputFormat(result.publicKey, outputFormat),
    privateKey: convertToOutputFormat(result.secretKey, outputFormat),
  };
}

export function crypto_sign_seed_keypair(
  seed: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): KeyPair;
export function crypto_sign_seed_keypair(
  seed: Uint8Array,
  outputFormat: StringOutputFormat
): StringKeyPair;
export function crypto_sign_seed_keypair(
  seed: Uint8Array,
  outputFormat: OutputFormat
): unknown {
  const result = global.jsi_crypto_sign_seed_keypair(toArrayBuffer(seed));
  return {
    keyType: 'ed25519',
    publicKey: convertToOutputFormat(result.publicKey, outputFormat),
    privateKey: convertToOutputFormat(result.secretKey, outputFormat),
  };
}

export function crypto_sign_detached(
  message: string | Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_sign_detached(
  message: string | Uint8Array,
  privateKey: Uint8Array,
  outputFormat: StringOutputFormat
): string;
export function crypto_sign_detached(
  message: string | Uint8Array,
  privateKey: Uint8Array,
  outputFormat: OutputFormat
): unknown {
  let result: ArrayBuffer;
  const messageParam =
    typeof message === 'string' ? message : toArrayBuffer(message);
  result = global.jsi_crypto_sign_detached(
    messageParam,
    toArrayBuffer(privateKey)
  );
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_sign_verify_detached(
  signature: Uint8Array,
  message: string | Uint8Array,
  publicKey: Uint8Array
): boolean {
  let result: boolean;
  const messageParam =
    typeof message === 'string' ? message : toArrayBuffer(message);
  result = global.jsi_crypto_sign_verify_detached(
    toArrayBuffer(signature),
    messageParam,
    toArrayBuffer(publicKey)
  );
  return result;
}

export function crypto_secretbox_easy(
  message: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_secretbox_easy(
  message: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat
): string;
export function crypto_secretbox_easy(
  message: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: OutputFormat
): unknown {
  let result: ArrayBuffer;
  const messageParam =
    typeof message === 'string' ? message : toArrayBuffer(message);
  result = global.jsi_crypto_secretbox_easy(
    messageParam,
    toArrayBuffer(nonce),
    toArrayBuffer(key)
  );
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_secretbox_open_easy(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_secretbox_open_easy(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat
): string;
export function crypto_secretbox_open_easy(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: OutputFormat
): unknown {
  let result: ArrayBuffer;
  const ciphertextParam =
    typeof ciphertext === 'string' ? ciphertext : toArrayBuffer(ciphertext);
  result = global.jsi_crypto_secretbox_open_easy(
    ciphertextParam,
    toArrayBuffer(nonce),
    toArrayBuffer(key)
  );
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_box_easy(
  message: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_box_easy(
  message: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat: StringOutputFormat
): string;
export function crypto_box_easy(
  message: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat: OutputFormat
): unknown {
  let result: ArrayBuffer;
  const messageParam =
    typeof message === 'string' ? message : toArrayBuffer(message);
  result = global.jsi_crypto_box_easy(
    messageParam,
    toArrayBuffer(nonce),
    toArrayBuffer(publicKey),
    toArrayBuffer(privateKey)
  );
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_box_open_easy(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_box_open_easy(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat: StringOutputFormat
): string;
export function crypto_box_open_easy(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat: OutputFormat
): unknown {
  let result: ArrayBuffer;
  const ciphertextParam =
    typeof ciphertext === 'string' ? ciphertext : toArrayBuffer(ciphertext);
  result = global.jsi_crypto_box_open_easy(
    ciphertextParam,
    toArrayBuffer(nonce),
    toArrayBuffer(publicKey),
    toArrayBuffer(privateKey)
  );
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_box_seal(
  ciphertext: string | Uint8Array,
  publicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_box_seal(
  ciphertext: string | Uint8Array,
  publicKey: Uint8Array,
  outputFormat: StringOutputFormat
): string;
export function crypto_box_seal(
  ciphertext: string | Uint8Array,
  publicKey: Uint8Array,
  outputFormat: OutputFormat
): unknown {
  let result: ArrayBuffer;
  const ciphertextParam =
    typeof ciphertext === 'string' ? ciphertext : toArrayBuffer(ciphertext);
  result = global.jsi_crypto_box_seal(
    ciphertextParam,
    toArrayBuffer(publicKey)
  );
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_box_seal_open(
  ciphertext: string | Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_box_seal_open(
  ciphertext: string | Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat: StringOutputFormat
): string;
export function crypto_box_seal_open(
  ciphertext: string | Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat: OutputFormat
): unknown {
  let result: ArrayBuffer;
  const ciphertextParam =
    typeof ciphertext === 'string' ? ciphertext : toArrayBuffer(ciphertext);
  result = global.jsi_crypto_box_seal_open(
    ciphertextParam,
    toArrayBuffer(publicKey),
    toArrayBuffer(privateKey)
  );
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_generichash(
  hash_length: number,
  message: string | Uint8Array,
  key?: Uint8Array | null | undefined,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_generichash(
  hash_length: number,
  message: string | Uint8Array,
  key: Uint8Array | null | undefined,
  outputFormat: StringOutputFormat
): string;
export function crypto_generichash(
  hash_length: number,
  message: string | Uint8Array,
  key: Uint8Array | null | undefined,
  outputFormat: OutputFormat
): unknown {
  const messageParam =
    typeof message === 'string' ? message : toArrayBuffer(message);
  const result = global.jsi_crypto_generichash(
    hash_length,
    messageParam,
    key ? toArrayBuffer(key) : undefined
  );
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_pwhash(
  keyLength: number,
  password: string | Uint8Array,
  salt: Uint8Array,
  opsLimit: number,
  memLimit: number,
  algorithm: number,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_pwhash(
  keyLength: number,
  password: string | Uint8Array,
  salt: Uint8Array,
  opsLimit: number,
  memLimit: number,
  algorithm: number,
  outputFormat: StringOutputFormat
): string;
export function crypto_pwhash(
  keyLength: number,
  password: string | Uint8Array,
  salt: Uint8Array,
  opsLimit: number,
  memLimit: number,
  algorithm: number,
  outputFormat: OutputFormat
): unknown {
  if (salt.length !== crypto_pwhash_SALTBYTES) {
    throw new Error('invalid salt length');
  }
  let result: ArrayBuffer;
  const passwordParam =
    typeof password === 'string' ? password : toArrayBuffer(password);
  result = global.jsi_crypto_pwhash(
    keyLength,
    passwordParam,
    toArrayBuffer(salt),
    opsLimit,
    memLimit,
    algorithm
  );
  return convertToOutputFormat(result, outputFormat);
}
export function crypto_sign_ed25519_pk_to_curve25519(
  publicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
) {
  const result = global.jsi_crypto_sign_ed25519_pk_to_curve25519(
    toArrayBuffer(publicKey)
  );
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_kdf_derive_from_key(
  subkey_len: number,
  subkey_id: number,
  ctx: string,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_kdf_derive_from_key(
  subkey_len: number,
  subkey_id: number,
  ctx: string,
  key: Uint8Array,
  outputFormat: StringOutputFormat
): string;
export function crypto_kdf_derive_from_key(
  subkey_len: number,
  subkey_id: number,
  ctx: string,
  key: Uint8Array,
  outputFormat: OutputFormat
): unknown {
  const result = global.jsi_crypto_kdf_derive_from_key(
    subkey_len,
    subkey_id,
    ctx,
    toArrayBuffer(key)
  );
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_aead_xchacha20poly1305_ietf_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_aead_xchacha20poly1305_ietf_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat
): string;
export function crypto_aead_xchacha20poly1305_ietf_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  _secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: OutputFormat
): unknown {
  let result: ArrayBuffer;
  const messageParam =
    typeof message === 'string' ? message : toArrayBuffer(message);
  if (typeof additional_data !== 'string') {
    throw new Error(
      'crypto_aead_xchacha20poly1305_ietf_encrypt: input type not yet implemented'
    );
  }
  result = global.jsi_crypto_aead_xchacha20poly1305_ietf_encrypt(
    messageParam,
    additional_data,
    toArrayBuffer(public_nonce),
    toArrayBuffer(key)
  );
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_aead_xchacha20poly1305_ietf_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_aead_xchacha20poly1305_ietf_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat
): string;
export function crypto_aead_xchacha20poly1305_ietf_decrypt(
  _secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: OutputFormat
): unknown {
  let result: ArrayBuffer;
  if (typeof ciphertext === 'string') {
    throw new Error(
      'crypto_aead_xchacha20poly1305_ietf_decrypt: input type not yet implemented'
    );
  }
  if (typeof additional_data !== 'string') {
    throw new Error(
      'crypto_aead_xchacha20poly1305_ietf_decrypt: input type not yet implemented'
    );
  }
  const ciphertextParam =
    typeof ciphertext === 'string' ? ciphertext : toArrayBuffer(ciphertext);
  result = global.jsi_crypto_aead_xchacha20poly1305_ietf_decrypt(
    ciphertextParam,
    additional_data,
    toArrayBuffer(public_nonce),
    toArrayBuffer(key)
  );
  return convertToOutputFormat(result, outputFormat);
}

export function _unstable_crypto_kdf_hkdf_sha256_extract(
  key: Uint8Array,
  salt: Uint8Array
) {
  return new Uint8Array(
    global.jsi_crypto_kdf_hkdf_sha256_extract(
      toArrayBuffer(key),
      toArrayBuffer(salt)
    )
  );
}

export function _unstable_crypto_kdf_hkdf_sha256_expand(
  key: Uint8Array,
  info: string,
  length: number
) {
  return new Uint8Array(
    global.jsi_crypto_kdf_hkdf_sha256_expand(toArrayBuffer(key), info, length)
  );
}

// add no-op ready to match the libsodium-wrappers API
export const ready: Promise<void> = new Promise((resolve) => resolve());

// add no-op ready to match the react-nativ-libsodium API for web
export const loadSumoVersion = () => undefined;

export default {
  crypto_auth,
  crypto_auth_verify,
  crypto_auth_BYTES,
  crypto_auth_KEYBYTES,
  crypto_auth_keygen,
  crypto_aead_xchacha20poly1305_ietf_decrypt,
  crypto_aead_xchacha20poly1305_ietf_encrypt,
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  crypto_box_easy,
  crypto_box_seed_keypair,
  crypto_box_keypair,
  crypto_box_NONCEBYTES,
  crypto_box_open_easy,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_generichash,
  crypto_generichash_BYTES,
  crypto_generichash_BYTES_MIN,
  crypto_generichash_BYTES_MAX,
  crypto_generichash_KEYBYTES,
  crypto_generichash_KEYBYTES_MIN,
  crypto_generichash_KEYBYTES_MAX,
  crypto_kdf_derive_from_key,
  crypto_kdf_CONTEXTBYTES,
  crypto_kdf_KEYBYTES,
  crypto_kdf_keygen,
  crypto_pwhash,
  crypto_sign_ed25519_pk_to_curve25519,
  crypto_pwhash_ALG_DEFAULT,
  crypto_pwhash_BYTES_MAX,
  crypto_pwhash_BYTES_MIN,
  crypto_pwhash_MEMLIMIT_INTERACTIVE,
  crypto_pwhash_OPSLIMIT_INTERACTIVE,
  crypto_pwhash_SALTBYTES,
  crypto_pwhash_ALG_ARGON2ID13,
  crypto_secretbox_easy,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_keygen,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_open_easy,
  crypto_sign_detached,
  crypto_sign_keypair,
  crypto_sign_verify_detached,
  from_base64,
  memzero,
  randombytes_buf,
  randombytes_uniform,
  ready,
  to_base64,
  to_hex,
  to_string,
  _unstable_crypto_kdf_hkdf_sha256_BYTES_MAX,
  _unstable_crypto_kdf_hkdf_sha256_BYTES_MIN,
  _unstable_crypto_kdf_hkdf_sha256_KEYBYTES,
  _unstable_crypto_kdf_hkdf_sha256_extract,
  _unstable_crypto_kdf_hkdf_sha256_expand,
};
