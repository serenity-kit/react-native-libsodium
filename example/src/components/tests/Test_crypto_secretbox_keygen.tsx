import React from 'react';
import { Text } from 'react-native';
import sodium from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  outputFormat?: 'uint8array' | 'base64' | 'hex' | null;
};

export const Test_crypto_secretbox_keygen: React.FC<Props> = ({
  outputFormat,
}) => {
  const key = sodium.crypto_secretbox_keygen(outputFormat);

  return (
    <>
      <FunctionStatus name="crypto_secretbox_keygen" success={true}>
        <Text>{key}</Text>
      </FunctionStatus>
    </>
  );
};
