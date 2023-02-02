import {
  base64_variants,
  crypto_aead_xchacha20poly1305_ietf_decrypt,
  crypto_aead_xchacha20poly1305_ietf_encrypt,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  from_base64,
  randombytes_buf,
  to_base64,
} from 'react-native-libsodium';

export const encryptAndDecryptImage = (contentAsBas64: string) => {
  const key = crypto_aead_xchacha20poly1305_ietf_keygen();
  const publicNonce = randombytes_buf(24);
  const additionalData = '';
  const content = from_base64(contentAsBas64, base64_variants.ORIGINAL);
  const ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
    content,
    additionalData,
    null,
    publicNonce,
    key
  );

  const decryptedContent = crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    additionalData,
    publicNonce,
    key
  );
  if (content.length !== decryptedContent.length) {
    throw new Error('encryptAndDecryptImage failed: length mismatch');
  }
  const result = to_base64(decryptedContent, base64_variants.ORIGINAL);
  if (result !== contentAsBas64) {
    throw new Error('encryptAndDecryptImage failed: content mismatch');
  }
  return result;
};
