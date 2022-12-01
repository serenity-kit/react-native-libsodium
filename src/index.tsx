export enum base64_variants {
  ORIGINAL,
  ORIGINAL_NO_PADDING,
  URLSAFE,
  URLSAFE_NO_PADDING,
}

declare global {
  function multiply(a: number, b: number): number;
  function from_base64(input: string, variant?: base64_variants): Uint8Array;
  function to_base64_from_string(
    input: string,
    variant: base64_variants
  ): string;
  function to_base64_from_uint8Array(
    input: Uint8Array,
    variant: base64_variants
  ): string;
}

export const multiply = global.multiply;

export const from_base64 = global.from_base64;

export const to_base64 = (
  input: string | Uint8Array,
  variant?: base64_variants
) => {
  const variantToUse = variant || base64_variants.URLSAFE_NO_PADDING;
  if (typeof input === 'string') {
    return global.to_base64_from_string(input, variantToUse);
  } else {
    return global.to_base64_from_uint8Array(input, variantToUse);
  }
};
