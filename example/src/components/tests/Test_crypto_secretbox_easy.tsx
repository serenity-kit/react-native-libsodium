import { Buffer } from 'buffer';
import React from 'react';
import {
  crypto_secretbox_easy,
  crypto_secretbox_keygen,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_open_easy,
  randombytes_buf,
} from 'react-native-libsodium';
import { isStringUtf8ArrayEquivalent } from '../../utils/isStringUtf8ArrayEquivalent';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  message: string | Uint8Array;
};

export const Test_crypto_secretbox_easy: React.FC<Props> = ({ message }) => {
  const key = crypto_secretbox_keygen();
  const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES);
  const ciphertext = crypto_secretbox_easy(message, nonce, key);
  const decryptedMessage = crypto_secretbox_open_easy(ciphertext, nonce, key);

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
        name="crypto_secretbox_easy"
        success={typeof ciphertext === 'object' && verifies()}
      />
    </>
  );
};
