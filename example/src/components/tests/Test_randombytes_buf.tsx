import React from 'react';
import { randombytes_buf } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

export const Test_randombytes_buf: React.FC = () => {
  return (
    <>
      <FunctionStatus
        name="randombytes_buf"
        success={
          randombytes_buf(1).length === 1 &&
          randombytes_buf(3).length === 3 &&
          randombytes_buf(9).length === 9
        }
      />
    </>
  );
};
