import React from 'react';
import { crypto_kdf_keygen } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  outputFormat?: any;
};

export const Test_crypto_kdf_keygen: React.FC<Props> = ({ outputFormat }) => {
  const key = crypto_kdf_keygen(outputFormat);

  return (
    <>
      <FunctionStatus
        name="crypto_kdf_keygen"
        success={true}
        output={key}
        inputs={{
          outputFormat,
        }}
      />
    </>
  );
};
