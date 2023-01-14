import React from 'react';
import { Text } from 'react-native';
import { crypto_sign_verify_detached } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  signature: Uint8Array;
  message: string | Uint8Array;
  publicKey: Uint8Array;
};

export const Test_crypto_sign_verify_detached: React.FC<Props> = ({
  signature,
  message,
  publicKey,
}) => {
  const verifies = crypto_sign_verify_detached(signature, message, publicKey);

  return (
    <>
      <FunctionStatus name="crypto_sign_verify_detached" success={true}>
        <Text>{verifies ? '(verifies)' : '(fails)'}</Text>
      </FunctionStatus>
    </>
  );
};
