import React from 'react';
import { Text } from 'react-native';
import {
  to_base64,
  crypto_aead_xchacha20poly1305_ietf_encrypt,
} from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  message: string | Uint8Array;
  additionalData: string;
  nonce: Uint8Array;
  symmetricKey: Uint8Array;
};

export const Test_crypto_aead_xchacha20poly1305_ietf_encrypt: React.FC<
  Props
> = ({ message, additionalData, nonce, symmetricKey }) => {
  const ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
    message,
    additionalData,
    null,
    nonce,
    symmetricKey
  );

  return (
    <>
      <FunctionStatus name="aead_xchacha20poly1305_ietf_encrypt" success={true}>
        <Text>{to_base64(ciphertext)}</Text>
      </FunctionStatus>
    </>
  );
};
