import React from 'react';
import { from_string } from 'react-native-libsodium';
import { isEqualUint8Array } from '../../utils/isEqualUint8Array';
import { FunctionStatus } from '../FunctionStatus';

export const Test_from_string: React.FC = () => {
  let throwErrorForInvalidInput = false;
  try {
    from_string('bla');
  } catch (e) {
    throwErrorForInvalidInput = true;
  }

  return (
    <>
      <FunctionStatus
        name="from_string"
        success={
          isEqualUint8Array(from_string(''), new Uint8Array([])) &&
          isEqualUint8Array(
            from_string('this is a test'),
            new Uint8Array([
              116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116,
            ])
          ) &&
          throwErrorForInvalidInput
        }
      />
    </>
  );
};
