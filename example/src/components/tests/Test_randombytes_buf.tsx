import React from 'react';
import { Text } from 'react-native';
import sodium, { to_base64 } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  length: number;
};

export const Test_randombytes_buf: React.FC<Props> = ({ length }) => {
  const randomData = sodium.randombytes_buf(length);

  return (
    <>
      <FunctionStatus
        name="randombytes_buf"
        success={randomData.length === length}
      >
        <Text>{to_base64(randomData)}</Text>
      </FunctionStatus>
    </>
  );
};
