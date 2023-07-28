import React from 'react';
import {
  crypto_auth_KEYBYTES,
  crypto_auth_keygen,
} from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

export const Test_crypto_auth_keygen: React.FC = () => {
  return (
    <>
      <FunctionStatus
        name="crypto_auth_keygen"
        success={crypto_auth_keygen().length === crypto_auth_KEYBYTES}
      />
    </>
  );
};
