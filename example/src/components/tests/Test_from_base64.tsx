import React from 'react';
import { from_base64 } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

const expected = new Uint8Array([
  72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100,
]);

export const Test_from_base64: React.FC = () => {
  const input = 'SGVsbG8gV29ybGQ';
  const resultUint8Array = from_base64(input);

  const verifyExpected = () => {
    if (resultUint8Array.length !== expected.length) {
      return false;
    }

    for (var index = 0; index < resultUint8Array.length; index++) {
      if (expected[index] !== resultUint8Array[index]) {
        return false;
      }
    }
    return true;
  };

  return (
    <>
      <FunctionStatus
        name="from_base64"
        success={verifyExpected()}
        output={resultUint8Array}
      />
    </>
  );
};
