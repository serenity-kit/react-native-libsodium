import React from 'react';
import { to_hex } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

export const Test_to_hex: React.FC = () => {
  const input = 'Hello World';

  return (
    <>
      <FunctionStatus
        name="to_hex"
        success={to_hex(input) === '48656c6c6f20576f726c64'}
      />
    </>
  );
};
