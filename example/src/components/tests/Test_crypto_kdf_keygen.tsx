import React from 'react';
import { Text } from 'react-native';
import { crypto_kdf_keygen } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  outputFormat?: 'base64' | 'hex';
};

export const Test_crypto_kdf_keygen: React.FC<Props> = ({ outputFormat }) => {
  const key = crypto_kdf_keygen(outputFormat);

  return (
    <>
      <FunctionStatus name="crypto_kdf_keygen" success={true}>
        <Text>{key}</Text>
      </FunctionStatus>
    </>
  );
};
