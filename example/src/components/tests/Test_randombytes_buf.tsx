import React from 'react';
import { randombytes_buf } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  length: number;
};

export const Test_randombytes_buf: React.FC<Props> = ({ length }) => {
  const randomData = randombytes_buf(length);

  return (
    <>
      <FunctionStatus
        name="randombytes_buf"
        success={randomData.length === length}
        output={randomData}
      />
    </>
  );
};
