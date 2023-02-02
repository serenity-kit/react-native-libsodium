import React from 'react';
import {
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_keygen,
} from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

export const Test_crypto_secretbox_keygen: React.FC = () => {
  return (
    <>
      <FunctionStatus
        name="crypto_kdf_keygen"
        success={crypto_secretbox_keygen().length === crypto_secretbox_KEYBYTES}
      />
    </>
  );
};
