import React from 'react';
import {
  crypto_kdf_KEYBYTES,
  crypto_kdf_keygen,
  from_base64,
} from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  outputFormat?: any;
};

export const Test_crypto_kdf_keygen: React.FC<Props> = ({ outputFormat }) => {
  const key = crypto_kdf_keygen(outputFormat);

  const verifies = () => {
    const keyLength = key.length;
    if (outputFormat === 'base64') {
      return (
        typeof key === 'string' &&
        from_base64(key).length === crypto_kdf_KEYBYTES
      );
    } else if (outputFormat === 'hex') {
      return typeof key === 'string' && keyLength === crypto_kdf_KEYBYTES * 2;
    } else {
      return typeof key === 'object' && keyLength === crypto_kdf_KEYBYTES;
    }
  };

  return (
    <>
      <FunctionStatus
        name="crypto_kdf_keygen"
        success={verifies()}
        output={key}
      />
    </>
  );
};
