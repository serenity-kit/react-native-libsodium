import React from 'react';
import { crypto_secretbox_keygen } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  outputFormat?: any;
};

export const Test_crypto_secretbox_keygen: React.FC<Props> = ({
  outputFormat,
}) => {
  const key = crypto_secretbox_keygen(outputFormat);

  return (
    <>
      <FunctionStatus
        name="crypto_secretbox_keygen"
        success={true}
        output={key}
        inputs={{
          outputFormat,
        }}
      />
    </>
  );
};
