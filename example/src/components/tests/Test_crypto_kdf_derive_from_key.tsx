import React from 'react';
import { Text } from 'react-native';
import { to_base64, crypto_kdf_derive_from_key } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  subkeyLength: number;
  subkeyId: number;
  context: string;
  masterKey: Uint8Array;
};

export const Test_crypto_kdf_derive_from_key: React.FC<Props> = ({
  subkeyLength,
  subkeyId,
  context,
  masterKey,
}) => {
  const key = crypto_kdf_derive_from_key(
    subkeyLength,
    subkeyId,
    context,
    masterKey
  );

  return (
    <>
      <FunctionStatus name="crypto_kdf_derive_from_key" success={true}>
        <Text>{to_base64(key)}</Text>
      </FunctionStatus>
    </>
  );
};