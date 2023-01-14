import React from 'react';
import { Text } from 'react-native';
import { to_base64, crypto_secretbox_easy } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  message: string | Uint8Array;
  nonce: Uint8Array;
  symmetricKey: Uint8Array;
};

export const Test_crypto_secretbox_easy: React.FC<Props> = ({
  message,
  nonce,
  symmetricKey,
}) => {
  const ciphertext = crypto_secretbox_easy(message, nonce, symmetricKey);

  return (
    <>
      <FunctionStatus name="crypto_secretbox_easy" success={true}>
        <Text>{to_base64(ciphertext)}</Text>
      </FunctionStatus>
    </>
  );
};
