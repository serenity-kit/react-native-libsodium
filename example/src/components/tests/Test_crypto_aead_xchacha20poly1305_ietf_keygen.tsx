import React from 'react';
import {
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  from_base64,
} from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  outputFormat?: any;
};

export const Test_crypto_aead_xchacha20poly1305_ietf_keygen: React.FC<
  Props
> = ({ outputFormat }) => {
  const key = crypto_aead_xchacha20poly1305_ietf_keygen(outputFormat);

  const verifies = () => {
    const keyLength = key.length;
    if (outputFormat === 'base64') {
      return (
        typeof key === 'string' &&
        from_base64(key).length === crypto_aead_xchacha20poly1305_ietf_KEYBYTES
      );
    } else if (outputFormat === 'hex') {
      return (
        typeof key === 'string' &&
        keyLength === crypto_aead_xchacha20poly1305_ietf_KEYBYTES * 2
      );
    } else {
      return (
        typeof key === 'object' &&
        keyLength === crypto_aead_xchacha20poly1305_ietf_KEYBYTES
      );
    }
  };

  return (
    <>
      <FunctionStatus
        name="crypto_aead_xchacha20poly1305_ietf_keygen"
        success={verifies()}
      />
    </>
  );
};
