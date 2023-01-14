import React from 'react';
import { Text } from 'react-native';
import { from_base64 } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

const expected = new Uint8Array([
  72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100,
]);

export const Test_from_base64: React.FC = () => {
  const resultUint8Array = from_base64('SGVsbG8gV29ybGQ');

  return (
    <>
      <FunctionStatus
        name="from_base64"
        success={resultUint8Array === expected}
      >
        <Text>{resultUint8Array}</Text>
      </FunctionStatus>
    </>
  );
};
