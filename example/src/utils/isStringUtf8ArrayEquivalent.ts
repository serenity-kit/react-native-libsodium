import { isArrayEqual } from './isArrayEqual';

export const isStringUtf8ArrayEquivalent = (
  decryptedMessage: Uint8Array,
  message: string | Uint8Array
) => {
  if (typeof message === 'string') {
    // TODO: fix this when we implement string decryption support;
    return false;
  } else {
    return isArrayEqual(decryptedMessage, message);
  }
};
