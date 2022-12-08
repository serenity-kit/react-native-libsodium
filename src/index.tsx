export { to_string } from './libsodium-js-utils';

export enum base64_variants {
  ORIGINAL = 1,
  ORIGINAL_NO_PADDING = 3,
  URLSAFE = 5,
  URLSAFE_NO_PADDING = 7,
}

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

  function multiply(a: number, b: number): number;
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
  function jsi_crypto_secretbox_keygen(): ArrayBuffer;
  function jsi_crypto_aead_xchacha20poly1305_ietf_keygen(): ArrayBuffer;
  function jsi_crypto_kdf_keygen(): ArrayBuffer;
}

export const multiply = global.multiply;

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

export const crypto_secretbox_keygen = (): Uint8Array => {
  const result = global.jsi_crypto_secretbox_keygen();
  return new Uint8Array(result);
};

export const crypto_aead_xchacha20poly1305_ietf_keygen = (): Uint8Array => {
  const result = global.jsi_crypto_aead_xchacha20poly1305_ietf_keygen();
  return new Uint8Array(result);
};

export const crypto_kdf_keygen = (): Uint8Array => {
  const result = global.jsi_crypto_kdf_keygen();
  return new Uint8Array(result);
};

// add no-op ready to match the libsodium-wrappers API
export const ready: Promise<void> = new Promise((resolve) => resolve());
