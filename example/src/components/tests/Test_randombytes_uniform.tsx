import React from 'react';
import { randombytes_uniform } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  max: number;
};

export const Test_randombytes_uniform: React.FC<Props> = ({ max }) => {
  const randomData = randombytes_uniform(max);
  console.log('randomData', randomData);

  return (
    <>
      <FunctionStatus
        name="randombytes_uniform"
        success={randomData <= max}
        output={randomData}
        inputs={{
          max,
        }}
      />
    </>
  );
};
