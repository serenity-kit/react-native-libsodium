import React from 'react';
import { from_base64, to_base64 } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

const expected = 'SGVsbG8gV29ybGQ';

export const Test_to_base64: React.FC = () => {
  const input = 'Hello World';
  const resultBase64 = to_base64(input);
  const resultUint8Array = from_base64(resultBase64);
  const result2Base64 = to_base64(resultUint8Array);

  return (
    <>
      <FunctionStatus
        name="to_base64"
        success={resultBase64 === expected && result2Base64 === expected}
        output={resultBase64}
      />
    </>
  );
};
