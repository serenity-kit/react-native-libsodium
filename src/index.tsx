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
  var crypto_secretbox_KEYBYTES: number;
  var crypto_secretbox_NONCEBYTES: number;
  var crypto_pwhash_SALTBYTES: number;
  var crypto_pwhash_ALG_DEFAULT: number;
  var crypto_pwhash_OPSLIMIT_INTERACTIVE: number;
  var crypto_pwhash_MEMLIMIT_INTERACTIVE: number;
  var crypto_box_PUBLICKEYBYTES: number;
  var crypto_box_SECRETKEYBYTES: number;
  var crypto_aead_xchacha20poly1305_ietf_KEYBYTES: number;
  var crypto_kdf_KEYBYTES: number;

  function from_base64_to_arraybuffer(
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
}

export const crypto_secretbox_KEYBYTES = global.crypto_secretbox_KEYBYTES;
export const crypto_secretbox_NONCEBYTES = global.crypto_secretbox_NONCEBYTES;
export const crypto_pwhash_SALTBYTES = global.crypto_pwhash_SALTBYTES;
export const crypto_pwhash_ALG_DEFAULT = global.crypto_pwhash_ALG_DEFAULT;
export const crypto_pwhash_OPSLIMIT_INTERACTIVE =
  global.crypto_pwhash_OPSLIMIT_INTERACTIVE;
export const crypto_pwhash_MEMLIMIT_INTERACTIVE =
  global.crypto_pwhash_MEMLIMIT_INTERACTIVE;
export const crypto_box_PUBLICKEYBYTES = global.crypto_box_PUBLICKEYBYTES;
export const crypto_box_SECRETKEYBYTES = global.crypto_box_SECRETKEYBYTES;
export const crypto_aead_xchacha20poly1305_ietf_KEYBYTES =
  global.crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
export const crypto_kdf_KEYBYTES = global.crypto_kdf_KEYBYTES;

export const from_base64 = (
  input: string,
  variant?: base64_variants
): Uint8Array => {
  const variantToUse = variant || base64_variants.URLSAFE_NO_PADDING;
  const result = global.from_base64_to_arraybuffer(input, variantToUse);
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

// add no-op ready to match the libsodium-wrappers API
export const ready: Promise<void> = new Promise((resolve) => resolve());
