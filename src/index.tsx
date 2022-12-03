export { to_string } from './libsodium-js-utils';

export enum base64_variants {
  ORIGINAL = 1,
  ORIGINAL_NO_PADDING = 3,
  URLSAFE = 5,
  URLSAFE_NO_PADDING = 7,
}

declare global {
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
  var crypto_secretbox_KEYBYTES: number;
}

export const multiply = global.multiply;

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

export const crypto_secretbox_KEYBYTES = global.crypto_secretbox_KEYBYTES;
