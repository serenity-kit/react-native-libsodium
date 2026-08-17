export { base64_variants, to_string } from './libsodium-js-utils';
import type {
  KeyPair,
  MessageTag,
  StringKeyPair,
  StringMessageTag,
} from './libsodium-types';
import type {
  StateAddress,
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
  var jsi_crypto_hash_BYTES: number;
  var jsi_crypto_hash_sha256_BYTES: number;
  var jsi_crypto_hash_sha512_BYTES: number;
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
  var jsi_crypto_secretstream_xchacha20poly1305_ABYTES: number;
  var jsi_crypto_secretstream_xchacha20poly1305_HEADERBYTES: number;
  var jsi_crypto_secretstream_xchacha20poly1305_KEYBYTES: number;
  var jsi_crypto_secretstream_xchacha20poly1305_TAG_MESSAGE: number;
  var jsi_crypto_secretstream_xchacha20poly1305_TAG_PUSH: number;
  var jsi_crypto_secretstream_xchacha20poly1305_TAG_REKEY: number;
  var jsi_crypto_secretstream_xchacha20poly1305_TAG_FINAL: number;

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
  function jsi_memcmp(
    b1: ArrayBuffer,
    b1Offset: number,
    b2: ArrayBuffer,
    b2Offset: number,
    length: number
  ): boolean;
  function jsi_memzero(
    buffer: ArrayBuffer,
    offset: number,
    length: number
  ): void;
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
  function jsi_crypto_hash(message: string | ArrayBuffer): ArrayBuffer;
  function jsi_crypto_hash_sha256(message: string | ArrayBuffer): ArrayBuffer;
  function jsi_crypto_hash_sha512(message: string | ArrayBuffer): ArrayBuffer;
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
    additionalData: string | ArrayBuffer | null,
    public_nonce: ArrayBuffer,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_aead_xchacha20poly1305_ietf_decrypt(
    ciphertext: string | ArrayBuffer,
    additionalData: string | ArrayBuffer | null,
    public_nonce: ArrayBuffer,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_secretstream_xchacha20poly1305_keygen(): ArrayBuffer;
  function jsi_crypto_secretstream_xchacha20poly1305_init_push(
    key: ArrayBuffer
  ): {
    state: ArrayBuffer;
    header: ArrayBuffer;
  };
  function jsi_crypto_secretstream_xchacha20poly1305_push(
    state: ArrayBuffer,
    message: string | ArrayBuffer,
    additionalData: string | ArrayBuffer | null,
    tag: number
  ): ArrayBuffer;
  function jsi_crypto_secretstream_xchacha20poly1305_init_pull(
    header: ArrayBuffer,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_secretstream_xchacha20poly1305_pull(
    state: ArrayBuffer,
    cipher: string | ArrayBuffer,
    additionalData: string | ArrayBuffer | null
  ): { message: ArrayBuffer; tag: number } | false;
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
export const crypto_hash_BYTES = global.jsi_crypto_hash_BYTES;
export const crypto_hash_sha256_BYTES = global.jsi_crypto_hash_sha256_BYTES;
export const crypto_hash_sha512_BYTES = global.jsi_crypto_hash_sha512_BYTES;
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
export const crypto_secretstream_xchacha20poly1305_ABYTES =
  global.jsi_crypto_secretstream_xchacha20poly1305_ABYTES;
export const crypto_secretstream_xchacha20poly1305_HEADERBYTES =
  global.jsi_crypto_secretstream_xchacha20poly1305_HEADERBYTES;
export const crypto_secretstream_xchacha20poly1305_KEYBYTES =
  global.jsi_crypto_secretstream_xchacha20poly1305_KEYBYTES;
export const crypto_secretstream_xchacha20poly1305_TAG_MESSAGE =
  global.jsi_crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
export const crypto_secretstream_xchacha20poly1305_TAG_PUSH =
  global.jsi_crypto_secretstream_xchacha20poly1305_TAG_PUSH;
export const crypto_secretstream_xchacha20poly1305_TAG_REKEY =
  global.jsi_crypto_secretstream_xchacha20poly1305_TAG_REKEY;
export const crypto_secretstream_xchacha20poly1305_TAG_FINAL =
  global.jsi_crypto_secretstream_xchacha20poly1305_TAG_FINAL;

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

export function memcmp(b1: Uint8Array, b2: Uint8Array): boolean {
  if (!(b1 instanceof Uint8Array && b2 instanceof Uint8Array)) {
    throw new TypeError('Only Uint8Array instances can be compared');
  }
  if (b1.length !== b2.length) {
    throw new TypeError('Only instances of identical length can be compared');
  }
  // the views' underlying buffers are passed with their own offsets so a
  // subarray is compared where it lies — copying the operands out would leave
  // a second, unwiped copy of the compared secret on the heap
  const b1Buffer = b1.buffer;
  const b2Buffer = b2.buffer;
  if (!(b1Buffer instanceof ArrayBuffer && b2Buffer instanceof ArrayBuffer)) {
    throw new TypeError(
      'Only ArrayBuffer backed Uint8Array instances can be compared'
    );
  }
  return global.jsi_memcmp(
    b1Buffer,
    b1.byteOffset,
    b2Buffer,
    b2.byteOffset,
    b1.byteLength
  );
}

export function memzero(bytes: Uint8Array): void {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('Only Uint8Array instances can be wiped');
  }
  // the view's underlying buffer is passed to sodium_memzero so the bytes
  // are wiped in place instead of on a copy
  const buffer = bytes.buffer;
  if (!(buffer instanceof ArrayBuffer)) {
    throw new TypeError(
      'Only ArrayBuffer backed Uint8Array instances can be wiped'
    );
  }
  global.jsi_memzero(buffer, bytes.byteOffset, bytes.byteLength);
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

export function crypto_hash(
  message: string | Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_hash(
  message: string | Uint8Array,
  outputFormat: StringOutputFormat
): string;
export function crypto_hash(
  message: string | Uint8Array,
  outputFormat: OutputFormat
): unknown {
  const messageParam =
    typeof message === 'string' ? message : toArrayBuffer(message);
  const result = global.jsi_crypto_hash(messageParam);
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_hash_sha256(
  message: string | Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_hash_sha256(
  message: string | Uint8Array,
  outputFormat: StringOutputFormat
): string;
export function crypto_hash_sha256(
  message: string | Uint8Array,
  outputFormat: OutputFormat
): unknown {
  const messageParam =
    typeof message === 'string' ? message : toArrayBuffer(message);
  const result = global.jsi_crypto_hash_sha256(messageParam);
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_hash_sha512(
  message: string | Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_hash_sha512(
  message: string | Uint8Array,
  outputFormat: StringOutputFormat
): string;
export function crypto_hash_sha512(
  message: string | Uint8Array,
  outputFormat: OutputFormat
): unknown {
  const messageParam =
    typeof message === 'string' ? message : toArrayBuffer(message);
  const result = global.jsi_crypto_hash_sha512(messageParam);
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
  const additionalDataParam =
    additional_data == null || typeof additional_data === 'string'
      ? additional_data
      : toArrayBuffer(additional_data);
  result = global.jsi_crypto_aead_xchacha20poly1305_ietf_encrypt(
    messageParam,
    additionalDataParam,
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
  const ciphertextParam =
    typeof ciphertext === 'string' ? ciphertext : toArrayBuffer(ciphertext);
  const additionalDataParam =
    additional_data == null || typeof additional_data === 'string'
      ? additional_data
      : toArrayBuffer(additional_data);
  result = global.jsi_crypto_aead_xchacha20poly1305_ietf_decrypt(
    ciphertextParam,
    additionalDataParam,
    toArrayBuffer(public_nonce),
    toArrayBuffer(key)
  );
  return convertToOutputFormat(result, outputFormat);
}

// The secretstream state is an opaque handle. On native it is the raw
// crypto_secretstream_xchacha20poly1305_state bytes in an ArrayBuffer which
// push and pull advance in place. It is typed as StateAddress to match the
// libsodium-wrappers API and must not be inspected or modified by callers.
export function crypto_secretstream_xchacha20poly1305_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_secretstream_xchacha20poly1305_keygen(
  outputFormat: StringOutputFormat
): string;
export function crypto_secretstream_xchacha20poly1305_keygen(
  outputFormat: OutputFormat
): unknown {
  const result = global.jsi_crypto_secretstream_xchacha20poly1305_keygen();
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_secretstream_xchacha20poly1305_init_push(
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null
): { state: StateAddress; header: Uint8Array };
export function crypto_secretstream_xchacha20poly1305_init_push(
  key: Uint8Array,
  outputFormat: StringOutputFormat
): { state: StateAddress; header: string };
export function crypto_secretstream_xchacha20poly1305_init_push(
  key: Uint8Array,
  outputFormat: OutputFormat
): unknown {
  const result = global.jsi_crypto_secretstream_xchacha20poly1305_init_push(
    toArrayBuffer(key)
  );
  return {
    state: result.state as unknown as StateAddress,
    header: convertToOutputFormat(result.header, outputFormat),
  };
}

export function crypto_secretstream_xchacha20poly1305_push(
  state_address: StateAddress,
  message_chunk: string | Uint8Array,
  ad: string | Uint8Array | null,
  tag: number,
  outputFormat?: Uint8ArrayOutputFormat | null
): Uint8Array;
export function crypto_secretstream_xchacha20poly1305_push(
  state_address: StateAddress,
  message_chunk: string | Uint8Array,
  ad: string | Uint8Array | null,
  tag: number,
  outputFormat: StringOutputFormat
): string;
export function crypto_secretstream_xchacha20poly1305_push(
  state_address: StateAddress,
  message_chunk: string | Uint8Array,
  ad: string | Uint8Array | null,
  tag: number,
  outputFormat: OutputFormat
): unknown {
  if (tag == null) {
    throw new TypeError('tag cannot be null or undefined');
  }
  // eslint-disable-next-line no-bitwise
  if (typeof tag !== 'number' || (tag | 0) !== tag || tag < 0) {
    throw new TypeError('tag must be an unsigned integer');
  }
  const messageParam =
    typeof message_chunk === 'string'
      ? message_chunk
      : toArrayBuffer(message_chunk);
  const adParam =
    ad == null ? null : typeof ad === 'string' ? ad : toArrayBuffer(ad);
  const result = global.jsi_crypto_secretstream_xchacha20poly1305_push(
    state_address as unknown as ArrayBuffer,
    messageParam,
    adParam,
    tag
  );
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_secretstream_xchacha20poly1305_init_pull(
  header: Uint8Array,
  key: Uint8Array
): StateAddress {
  const result = global.jsi_crypto_secretstream_xchacha20poly1305_init_pull(
    toArrayBuffer(header),
    toArrayBuffer(key)
  );
  return result as unknown as StateAddress;
}

export function crypto_secretstream_xchacha20poly1305_pull(
  state_address: StateAddress,
  cipher: string | Uint8Array,
  ad?: string | Uint8Array | null,
  outputFormat?: Uint8ArrayOutputFormat | null
): MessageTag | false;
export function crypto_secretstream_xchacha20poly1305_pull(
  state_address: StateAddress,
  cipher: string | Uint8Array,
  ad: string | Uint8Array | null,
  outputFormat: StringOutputFormat
): StringMessageTag | false;
export function crypto_secretstream_xchacha20poly1305_pull(
  state_address: StateAddress,
  cipher: string | Uint8Array,
  ad?: string | Uint8Array | null,
  outputFormat?: OutputFormat
): unknown {
  if (
    cipher instanceof Uint8Array &&
    cipher.length < crypto_secretstream_xchacha20poly1305_ABYTES
  ) {
    throw new TypeError('cipher is too short');
  }
  const cipherParam =
    typeof cipher === 'string' ? cipher : toArrayBuffer(cipher);
  const adParam =
    ad == null ? null : typeof ad === 'string' ? ad : toArrayBuffer(ad);
  const result = global.jsi_crypto_secretstream_xchacha20poly1305_pull(
    state_address as unknown as ArrayBuffer,
    cipherParam,
    adParam
  );
  // matching the libsodium-wrappers behavior of returning false instead of
  // throwing when the ciphertext is invalid
  if (result === false) {
    return false;
  }
  return {
    message: convertToOutputFormat(result.message, outputFormat),
    tag: result.tag,
  };
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
  crypto_hash,
  crypto_hash_BYTES,
  crypto_hash_sha256,
  crypto_hash_sha256_BYTES,
  crypto_hash_sha512,
  crypto_hash_sha512_BYTES,
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
  crypto_secretstream_xchacha20poly1305_ABYTES,
  crypto_secretstream_xchacha20poly1305_HEADERBYTES,
  crypto_secretstream_xchacha20poly1305_init_pull,
  crypto_secretstream_xchacha20poly1305_init_push,
  crypto_secretstream_xchacha20poly1305_KEYBYTES,
  crypto_secretstream_xchacha20poly1305_keygen,
  crypto_secretstream_xchacha20poly1305_pull,
  crypto_secretstream_xchacha20poly1305_push,
  crypto_secretstream_xchacha20poly1305_TAG_FINAL,
  crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
  crypto_secretstream_xchacha20poly1305_TAG_PUSH,
  crypto_secretstream_xchacha20poly1305_TAG_REKEY,
  crypto_sign_detached,
  crypto_sign_keypair,
  crypto_sign_verify_detached,
  from_base64,
  memcmp,
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
