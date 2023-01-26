import { Buffer } from 'buffer';
import React from 'react';
import {
  crypto_aead_xchacha20poly1305_ietf_decrypt,
  crypto_aead_xchacha20poly1305_ietf_encrypt,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  randombytes_buf,
} from 'react-native-libsodium';
import { isStringUtf8ArrayEquivalent } from '../../utils/isStringUtf8ArrayEquivalent';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  additionalData: string;
  message: string | Uint8Array;
};

export const Test_crypto_aead_xchacha20poly1305_ietf_decrypt: React.FC<
  Props
> = ({ additionalData, message }) => {
  const key = crypto_aead_xchacha20poly1305_ietf_keygen();
  const secretNonce = null;
  const publicNonce = randombytes_buf(
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );
  const ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
    message,
    additionalData,
    secretNonce,
    publicNonce,
    key
  );
  const decryptedMessage = crypto_aead_xchacha20poly1305_ietf_decrypt(
    secretNonce,
    ciphertext,
    additionalData,
    publicNonce,
    key
  );

  const verifies = () => {
    if (typeof message === 'string') {
      const decryptedMessageString = Buffer.from(
        decryptedMessage.buffer
      ).toString();
      return decryptedMessageString === message;
    } else {
      return isStringUtf8ArrayEquivalent(decryptedMessage, message);
    }
  };
  return (
    <>
      <FunctionStatus
        name="crypto_aead_xchacha20poly1305_ietf_decrypt"
        success={verifies()}
        output={decryptedMessage}
      />
    </>
  );
};
