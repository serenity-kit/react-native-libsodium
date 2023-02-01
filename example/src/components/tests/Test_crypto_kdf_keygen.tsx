import React from 'react';
import { crypto_kdf_KEYBYTES, crypto_kdf_keygen } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

export const Test_crypto_kdf_keygen: React.FC = () => {
  return (
    <>
      <FunctionStatus
        name="crypto_kdf_keygen"
        success={crypto_kdf_keygen().length === crypto_kdf_KEYBYTES}
      />
    </>
  );
};
