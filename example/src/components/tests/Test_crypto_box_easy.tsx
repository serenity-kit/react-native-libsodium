import { Buffer } from 'buffer';
import React from 'react';
import {
  crypto_box_easy,
  crypto_box_keypair,
  crypto_box_NONCEBYTES,
  crypto_box_open_easy,
  randombytes_buf,
} from 'react-native-libsodium';
import { isStringUtf8ArrayEquivalent } from '../../utils/isStringUtf8ArrayEquivalent';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  message: string | Uint8Array;
};

export const Test_crypto_box_easy: React.FC<Props> = ({ message }) => {
  const senderKeyPair = crypto_box_keypair();
  const receiverKeyPair = crypto_box_keypair();
  const nonce = randombytes_buf(crypto_box_NONCEBYTES);
  const ciphertext = crypto_box_easy(
    message,
    nonce,
    receiverKeyPair.publicKey,
    senderKeyPair.privateKey
  );
  const decryptedMessage = crypto_box_open_easy(
    ciphertext,
    nonce,
    senderKeyPair.publicKey,
    receiverKeyPair.privateKey
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
        name="crypto_box_easy"
        success={typeof ciphertext === 'object' && verifies()}
        output={ciphertext}
      />
    </>
  );
};
