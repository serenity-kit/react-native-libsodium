import React from 'react';
import { Text } from 'react-native';
import { to_base64, crypto_sign_detached } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  message: string | Uint8Array;
  privateKey: Uint8Array;
};

export const Test_crypto_sign_detached: React.FC<Props> = ({
  message,
  privateKey,
}) => {
  const signature = crypto_sign_detached(message, privateKey);

  return (
    <>
      <FunctionStatus name="crypto_sign_detached" success={true}>
        <Text>{to_base64(signature)}</Text>
      </FunctionStatus>
    </>
  );
};
