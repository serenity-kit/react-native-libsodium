import React from 'react';
import {
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_keygen,
  from_base64,
} from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  outputFormat?: any;
};

export const Test_crypto_secretbox_keygen: React.FC<Props> = ({
  outputFormat,
}) => {
  const key = crypto_secretbox_keygen(outputFormat);

  const verifies = () => {
    const keyLength = key.length;
    if (outputFormat === 'base64') {
      return (
        typeof key === 'string' &&
        from_base64(key).length === crypto_secretbox_KEYBYTES
      );
    } else if (outputFormat === 'hex') {
      return (
        typeof key === 'string' && keyLength === crypto_secretbox_KEYBYTES * 2
      );
    } else {
      return typeof key === 'object' && keyLength === crypto_secretbox_KEYBYTES;
    }
  };

  return (
    <>
      <FunctionStatus
        name="crypto_secretbox_keygen"
        success={verifies()}
        output={key}
      />
    </>
  );
};
