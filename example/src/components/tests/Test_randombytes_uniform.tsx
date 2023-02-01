import React from 'react';
import { randombytes_uniform } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

export const Test_randombytes_uniform: React.FC = () => {
  return (
    <>
      <FunctionStatus
        name="randombytes_uniform"
        success={
          randombytes_uniform(10) <= 10 &&
          randombytes_uniform(1) === 0 &&
          randombytes_uniform(0) === 0
        }
      />
    </>
  );
};
