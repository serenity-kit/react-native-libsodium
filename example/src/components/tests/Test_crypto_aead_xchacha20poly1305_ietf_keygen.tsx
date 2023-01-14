import React from 'react';
import { Text } from 'react-native';
import { crypto_aead_xchacha20poly1305_ietf_keygen } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  outputFormat?: 'base64' | 'hex';
};

export const Test_crypto_aead_xchacha20poly1305_ietf_keygen: React.FC<
  Props
> = ({ outputFormat }) => {
  const key = crypto_aead_xchacha20poly1305_ietf_keygen(outputFormat);

  return (
    <>
      <FunctionStatus
        name="crypto_aead_xchacha20poly1305_ietf_keygen"
        success={true}
      >
        <Text>{key}</Text>
      </FunctionStatus>
    </>
  );
};
