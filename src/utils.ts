import { base64_variants, OutputFormat } from './types';

export function convertToOutputFormat(
  input: ArrayBuffer,
  outputFormat: OutputFormat
) {
  if (outputFormat === 'base64') {
    return global.jsi_to_base64_from_arraybuffer(
      input,
      base64_variants.URLSAFE_NO_PADDING
    );
  }
  if (outputFormat === 'hex') {
    return global.jsi_to_hex_from_arraybuffer(input);
  }
  if (outputFormat === 'text') {
    throw new Error(
      '[ERR_ENCODING_INVALID_ENCODED_DATA]: The encoded data was not valid for encoding utf-8'
    );
  }
  return new Uint8Array(input);
}
