import React from 'react';
import { from_base64, to_base64 } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';
import { Header } from '../Header';
import { isArrayEqual } from '../../utils/isArrayEqual';

const expectedBase64 = 'SGVsbG8gV29ybGQ';

const expectedDecoded = new Uint8Array([
  72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100,
]);

export const Test_base64: React.FC = () => {
  const input = 'Hello World';
  const resultBase64 = to_base64(input);
  const resultUint8Array = from_base64(resultBase64);

  return (
    <>
      <Header>Base64</Header>
      <FunctionStatus
        name="to_base64"
        success={resultBase64 === expectedBase64}
        output={resultBase64}
        inputs={{
          input,
        }}
      />
      <FunctionStatus
        name="from_base64"
        success={isArrayEqual(resultUint8Array, expectedDecoded)}
        output={resultUint8Array}
        inputs={{
          input,
        }}
      />
    </>
  );
};
