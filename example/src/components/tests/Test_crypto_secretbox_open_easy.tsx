import React from 'react';
import { crypto_secretbox_open_easy } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';
import { isStringUtf8ArrayEquivalent } from '../../utils/isStringUtf8ArrayEquivalent';

type Props = {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  symmetricKey: Uint8Array;
  message: string | Uint8Array;
};

export const Test_crypto_secretbox_open_easy: React.FC<Props> = ({
  ciphertext,
  nonce,
  symmetricKey,
  message,
}) => {
  const decryptedMessage = crypto_secretbox_open_easy(
    ciphertext,
    nonce,
    symmetricKey
  );

  return (
    <>
      <FunctionStatus
        name="crypto_box_open_easy"
        success={isStringUtf8ArrayEquivalent(decryptedMessage, message)}
        output={decryptedMessage}
        inputs={{
          ciphertext,
          nonce,
          key: symmetricKey,
        }}
      />
    </>
  );
};
