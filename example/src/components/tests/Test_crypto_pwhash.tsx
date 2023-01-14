import React from 'react';
import { Text } from 'react-native';
import {
  to_base64,
  crypto_pwhash,
  crypto_pwhash_BYTES_MIN,
  crypto_pwhash_OPSLIMIT_INTERACTIVE,
  crypto_pwhash_MEMLIMIT_INTERACTIVE,
  crypto_pwhash_ALG_DEFAULT,
} from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  length?: number;
  password: string | Uint8Array;
  salt: Uint8Array;
  opsLimit?: number;
  memLimit?: number;
  algorithm?: number;
};

export const Test_crypto_pwhash: React.FC<Props> = ({
  length,
  password,
  salt,
  opsLimit,
  memLimit,
  algorithm,
}) => {
  const pwhashLength = length === undefined ? crypto_pwhash_BYTES_MIN : length;
  const pwhashOpsLimit =
    opsLimit === undefined ? crypto_pwhash_OPSLIMIT_INTERACTIVE : opsLimit;
  const pwhashMemLimit =
    memLimit === undefined ? crypto_pwhash_MEMLIMIT_INTERACTIVE : memLimit;
  const pwhashAlgorithm =
    algorithm === undefined ? crypto_pwhash_ALG_DEFAULT : algorithm;

  const pwhash = crypto_pwhash(
    pwhashLength,
    password,
    salt,
    pwhashOpsLimit,
    pwhashMemLimit,
    pwhashAlgorithm
  );

  return (
    <>
      <FunctionStatus name="crypto_pwhash" success={true}>
        <Text>{to_base64(pwhash)}</Text>
      </FunctionStatus>
    </>
  );
};
