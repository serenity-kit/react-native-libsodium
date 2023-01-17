import React from 'react';
import { randombytes_uniform } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  max: number;
};

export const Test_randombytes_uniform: React.FC<Props> = ({ max }) => {
  const randomData = randombytes_uniform(max);

  return (
    <>
      <FunctionStatus
        name="randombytes_uniform"
        success={randomData <= max}
        // NOTE: this is a way to fix a bug with
        // randombytes_buf() == 0 not showing up
        output={randomData || '0'}
      />
    </>
  );
};
