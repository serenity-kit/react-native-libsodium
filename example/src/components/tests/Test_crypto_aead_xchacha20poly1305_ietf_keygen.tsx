import React from 'react';
import { crypto_aead_xchacha20poly1305_ietf_keygen } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  outputFormat?: any;
};

export const Test_crypto_aead_xchacha20poly1305_ietf_keygen: React.FC<
  Props
> = ({ outputFormat }) => {
  const key = crypto_aead_xchacha20poly1305_ietf_keygen(outputFormat);

  return (
    <>
      <FunctionStatus
        name="crypto_aead_xchacha20poly1305_ietf_keygen"
        success={true}
        output={key}
        inputs={{
          outputFormat: outputFormat,
        }}
      />
    </>
  );
};
