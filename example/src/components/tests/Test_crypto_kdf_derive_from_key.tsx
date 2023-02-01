import React from 'react';
import {
  crypto_kdf_derive_from_key,
  crypto_kdf_keygen,
} from 'react-native-libsodium';
import { isArrayEqual } from '../../utils/isArrayEqual';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  subkeyLength: number;
};

export const Test_crypto_kdf_derive_from_key: React.FC<Props> = ({
  subkeyLength,
}) => {
  const masterKey = crypto_kdf_keygen();
  const key1 = crypto_kdf_derive_from_key(
    subkeyLength,
    1,
    'context_',
    masterKey
  );
  const key2 = crypto_kdf_derive_from_key(
    subkeyLength,
    2,
    'context_',
    masterKey
  );
  const key3 = crypto_kdf_derive_from_key(
    subkeyLength,
    1,
    'another_',
    masterKey
  );

  const verifies = () => {
    return (
      key1.length === subkeyLength &&
      !isArrayEqual(key1, masterKey) &&
      !isArrayEqual(key1, key2) &&
      !isArrayEqual(key1, key3)
    );
  };

  return (
    <>
      <FunctionStatus name="crypto_kdf_derive_from_key" success={verifies()} />
    </>
  );
};
