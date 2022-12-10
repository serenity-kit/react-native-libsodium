export type {
  KeyPair,
  KeyType,
  StringKeyPair,
  StringOutputFormat,
  Uint8ArrayOutputFormat,
} from 'libsodium-wrappers';
export { base64_variants, to_string } from './libsodium-js-utils';
import type {
  KeyPair,
  StringKeyPair,
  StringOutputFormat,
  Uint8ArrayOutputFormat,
} from 'libsodium-wrappers';
import { base64_variants } from './libsodium-js-utils';
import type { OutputFormat } from './types';
import { convertToOutputFormat } from './utils';

declare global {
  var jsi_crypto_secretbox_KEYBYTES: number;
  var jsi_crypto_secretbox_NONCEBYTES: number;
  var jsi_crypto_pwhash_SALTBYTES: number;
  var jsi_crypto_pwhash_ALG_DEFAULT: number;
  var jsi_crypto_pwhash_OPSLIMIT_INTERACTIVE: number;
  var jsi_crypto_pwhash_MEMLIMIT_INTERACTIVE: number;
  var jsi_crypto_box_PUBLICKEYBYTES: number;
  var jsi_crypto_box_SECRETKEYBYTES: number;
  var jsi_crypto_box_NONCEBYTES: number;
  var jsi_crypto_aead_xchacha20poly1305_ietf_KEYBYTES: number;
  var jsi_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: number;
  var jsi_crypto_kdf_KEYBYTES: number;
  var jsi_crypto_pwhash_BYTES_MIN: number;
  var jsi_crypto_pwhash_BYTES_MAX: number;

  function jsi_from_base64_to_arraybuffer(
    input: string,
    variant?: base64_variants
  ): ArrayBuffer;
  function jsi_to_base64_from_string(
    input: string,
    variant: base64_variants
  ): string;
  function jsi_to_base64_from_arraybuffer(
    input: ArrayBuffer,
    variant: base64_variants
  ): string;
  function jsi_to_hex_from_string(input: string): string;
  function jsi_to_hex_from_arraybuffer(input: ArrayBuffer): string;
  function jsi_randombytes_buf(length: number): ArrayBuffer;
  function jsi_randombytes_uniform(upper_bound: number): number;
  function jsi_crypto_secretbox_keygen(): ArrayBuffer;
  function jsi_crypto_aead_xchacha20poly1305_ietf_keygen(): ArrayBuffer;
  function jsi_crypto_kdf_keygen(): ArrayBuffer;
  function jsi_crypto_box_keypair(): {
    publicKey: ArrayBuffer;
    secretKey: ArrayBuffer;
  };
  function jsi_crypto_sign_keypair(): {
    publicKey: ArrayBuffer;
    secretKey: ArrayBuffer;
  };
  function jsi_crypto_sign_keypair_from_string(
    message: string,
    privateKey: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_sign_keypair_from_arraybuffer(
    message: ArrayBuffer,
    privateKey: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_sign_verify_detached_from_string(
    signature: ArrayBuffer,
    message: string,
    publicKey: ArrayBuffer
  ): boolean;
  function jsi_crypto_sign_verify_detached_from_arraybuffer(
    signature: ArrayBuffer,
    message: ArrayBuffer,
    publicKey: ArrayBuffer
  ): boolean;
  function jsi_crypto_secretbox_easy_from_string(
    message: string,
    nonce: ArrayBuffer,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_secretbox_easy_from_arraybuffer(
    message: ArrayBuffer,
    nonce: ArrayBuffer,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_secretbox_open_easy_from_string(
    ciphertext: string,
    nonce: ArrayBuffer,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_secretbox_open_easy_from_arraybuffer(
    ciphertext: ArrayBuffer,
    nonce: ArrayBuffer,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_box_easy_from_string(
    message: string,
    nonce: ArrayBuffer,
    publicKey: ArrayBuffer,
    secretKey: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_box_easy_from_arraybuffer(
    message: ArrayBuffer,
    nonce: ArrayBuffer,
    publicKey: ArrayBuffer,
    secretKey: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_box_open_easy_from_string(
    ciphertext: string,
    nonce: ArrayBuffer,
    publicKey: ArrayBuffer,
    secretKey: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_box_open_easy_from_arraybuffer(
    ciphertext: ArrayBuffer,
    nonce: ArrayBuffer,
    publicKey: ArrayBuffer,
    secretKey: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_pwhash_from_string(
    keyLength: number,
    password: string,
    salt: ArrayBuffer,
    opsLimit: number,
    memLimit: number,
    algorithm: number
  ): ArrayBuffer;
  function jsi_crypto_pwhash_from_arraybuffer(
    keyLength: number,
    password: ArrayBuffer,
    salt: ArrayBuffer,
    opsLimit: number,
    memLimit: number,
    algorithm: number
  ): ArrayBuffer;
  function jsi_crypto_kdf_derive_from_key(
    subkeyLength: number,
    subkeyId: number,
    context: string,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string(
    message: string,
    additionalData: string,
    nonce: ArrayBuffer,
    key: ArrayBuffer
  ): ArrayBuffer;
  function jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer(
    ciphertext: ArrayBuffer,
    additionalData: string,
    nonce: ArrayBuffer,
    key: ArrayBuffer
  ): ArrayBuffer;
}

export const crypto_secretbox_KEYBYTES = global.jsi_crypto_secretbox_KEYBYTES;
export const crypto_secretbox_NONCEBYTES =
  global.jsi_crypto_secretbox_NONCEBYTES;
export const crypto_pwhash_SALTBYTES = global.jsi_crypto_pwhash_SALTBYTES;
export const crypto_pwhash_ALG_DEFAULT = global.jsi_crypto_pwhash_ALG_DEFAULT;
export const crypto_pwhash_OPSLIMIT_INTERACTIVE =
  global.jsi_crypto_pwhash_OPSLIMIT_INTERACTIVE;
export const crypto_pwhash_MEMLIMIT_INTERACTIVE =
  global.jsi_crypto_pwhash_MEMLIMIT_INTERACTIVE;
export const crypto_box_PUBLICKEYBYTES = global.jsi_crypto_box_PUBLICKEYBYTES;
export const crypto_box_SECRETKEYBYTES = global.jsi_crypto_box_SECRETKEYBYTES;
export const crypto_box_NONCEBYTES = global.jsi_crypto_box_NONCEBYTES;
export const crypto_aead_xchacha20poly1305_ietf_KEYBYTES =
  global.jsi_crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
export const crypto_aead_xchacha20poly1305_ietf_NPUBBYTES =
  global.jsi_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
export const crypto_kdf_KEYBYTES = global.jsi_crypto_kdf_KEYBYTES;
export const crypto_pwhash_BYTES_MIN = global.jsi_crypto_pwhash_BYTES_MIN;
export const crypto_pwhash_BYTES_MAX = global.jsi_crypto_pwhash_BYTES_MAX;

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
  if (typeof input === 'string') {
    return global.jsi_to_base64_from_string(input, variantToUse);
  } else {
    return global.jsi_to_base64_from_arraybuffer(input.buffer, variantToUse);
  }
};

export function to_hex(input: string | Uint8Array): string {
  if (typeof input === 'string') {
    return global.jsi_to_hex_from_string(input);
  } else {
    return global.jsi_to_hex_from_arraybuffer(input.buffer);
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
) {
  const result = global.jsi_randombytes_buf(length);
  return convertToOutputFormat(result, outputFormat);
}

export function randombytes_uniform(upper_bound: number): number {
  return global.jsi_randombytes_uniform(upper_bound);
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
    keyType: 'curve25519',
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
  if (typeof message === 'string') {
    result = global.jsi_crypto_sign_keypair_from_string(
      message,
      privateKey.buffer
    );
  } else {
    result = global.jsi_crypto_sign_keypair_from_arraybuffer(
      message.buffer,
      privateKey.buffer
    );
  }
  return convertToOutputFormat(result, outputFormat);
}

export function crypto_sign_verify_detached(
  signature: Uint8Array,
  message: string | Uint8Array,
  publicKey: Uint8Array
): boolean {
  let result: boolean;
  if (typeof message === 'string') {
    result = global.jsi_crypto_sign_verify_detached_from_string(
      signature.buffer,
      message,
      publicKey.buffer
    );
  } else {
    result = global.jsi_crypto_sign_verify_detached_from_arraybuffer(
      signature.buffer,
      message.buffer,
      publicKey.buffer
    );
  }
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
  if (typeof message === 'string') {
    result = global.jsi_crypto_secretbox_easy_from_string(
      message,
      nonce.buffer,
      key.buffer
    );
  } else {
    result = global.jsi_crypto_secretbox_easy_from_arraybuffer(
      message.buffer,
      nonce.buffer,
      key.buffer
    );
  }
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
) {
  let result: ArrayBuffer;
  if (typeof ciphertext === 'string') {
    result = global.jsi_crypto_secretbox_open_easy_from_string(
      ciphertext,
      nonce.buffer,
      key.buffer
    );
  } else {
    result = global.jsi_crypto_secretbox_open_easy_from_arraybuffer(
      ciphertext.buffer,
      nonce.buffer,
      key.buffer
    );
  }
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
) {
  let result: ArrayBuffer;
  if (typeof message === 'string') {
    result = global.jsi_crypto_box_easy_from_string(
      message,
      nonce.buffer,
      publicKey.buffer,
      privateKey.buffer
    );
  } else {
    result = global.jsi_crypto_box_easy_from_arraybuffer(
      message.buffer,
      nonce.buffer,
      publicKey.buffer,
      privateKey.buffer
    );
  }
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
) {
  let result: ArrayBuffer;
  if (typeof ciphertext === 'string') {
    result = global.jsi_crypto_box_open_easy_from_string(
      ciphertext,
      nonce.buffer,
      publicKey.buffer,
      privateKey.buffer
    );
  } else {
    result = global.jsi_crypto_box_open_easy_from_arraybuffer(
      ciphertext.buffer,
      nonce.buffer,
      publicKey.buffer,
      privateKey.buffer
    );
  }
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
) {
  let result: ArrayBuffer;
  if (typeof password === 'string') {
    result = global.jsi_crypto_pwhash_from_string(
      keyLength,
      password,
      salt.buffer,
      opsLimit,
      memLimit,
      algorithm
    );
  } else {
    result = global.jsi_crypto_pwhash_from_arraybuffer(
      keyLength,
      password.buffer,
      salt.buffer,
      opsLimit,
      memLimit,
      algorithm
    );
  }
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
) {
  const result = global.jsi_crypto_kdf_derive_from_key(
    subkey_len,
    subkey_id,
    ctx,
    key.buffer
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
) {
  let result: ArrayBuffer;
  if (typeof message === 'string' && typeof additional_data === 'string') {
    result = global.jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string(
      message,
      additional_data,
      public_nonce.buffer,
      key.buffer
    );
  } else {
    throw new Error(
      'crypto_aead_xchacha20poly1305_ietf_encrypt: input type not yet implemented'
    );
  }
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
) {
  let result: ArrayBuffer;
  if (typeof ciphertext !== 'string' && typeof additional_data === 'string') {
    result =
      global.jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer(
        ciphertext.buffer,
        additional_data,
        public_nonce.buffer,
        key.buffer
      );
  } else {
    throw new Error(
      'crypto_aead_xchacha20poly1305_ietf_decrypt: input type not yet implemented'
    );
  }
  return convertToOutputFormat(result, outputFormat);
}

// add no-op ready to match the libsodium-wrappers API
export const ready: Promise<void> = new Promise((resolve) => resolve());
