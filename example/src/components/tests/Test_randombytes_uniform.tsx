import React from 'react';
import { Text } from 'react-native';
import sodium from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  max: number;
};

export const Test_randombytes_uniform: React.FC<Props> = ({ max }) => {
  const randomData = sodium.randombytes_uniform(max);

  return (
    <>
      <FunctionStatus name="randombytes_uniform" success={randomData <= max}>
        <Text>{randomData}</Text>
      </FunctionStatus>
    </>
  );
};
